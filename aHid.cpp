/*
 * aHid.cpp
 *
 *  Created on: 30 Oct. 2019
 *      Author: apaml
 */

#include "aHid.h"
#include <Windows.h>	// We require the datatypes from this header
#include <setupapi.h>	// setupapi.h provides the functions required to search for
// and identify our target USB device
#include <stdio.h>
#include <stdlib.h>		// Required for WM_DEVICECHANGE messages (plug and play USB detection)
#include <Dbt.h>	   	// Required for WM_DEVICECHANGE messages (plug and play USB detection)

using namespace std;
using namespace boost;

#ifndef _DEBUG
#define DEBUG_MESSAGE //
#endif
#ifdef _DEBUG
#define DEBUG_MESSAGE(msg) OutputDebugStringW ( msg)
#endif

/* The maximum number of characters that can be passed into the
 HidD_Get*String() functions without it failing. */
#define MAX_STRING_WCHARS 0xFFF

/* #define HIDAPI_USE_DDK */

// #include <winioctl.h>
#ifdef HIDAPI_USE_DDK
#include <hidsdi.h>
#endif

/* Copied from inc/ddk/hidclass.h, part of the Windows DDK. */
#define HID_OUT_CTL_CODE(id)  \
		CTL_CODE(FILE_DEVICE_KEYBOARD, (id), METHOD_OUT_DIRECT, FILE_ANY_ACCESS)
#define IOCTL_HID_GET_FEATURE                   HID_OUT_CTL_CODE(100)

#undef MIN
#define MIN(x,y) ((x) < (y)? (x): (y))

#ifdef _MSC_VER
/* Thanks Microsoft, but I know how to use strncpy(). */
#pragma warning(disable:4996)
#endif

#ifndef HIDAPI_USE_DDK

/* Since we're not building with the DDK, and the HID header
 files aren't part of the SDK, we have to define all this
 stuff here. In lookup_functions(), the function pointers
 defined below are set. */
typedef struct _HIDD_ATTRIBUTES {
	ULONG Size;
	USHORT VendorID;
	USHORT ProductID;
	USHORT VersionNumber;
} HIDD_ATTRIBUTES, *PHIDD_ATTRIBUTES;

typedef USHORT USAGE;

typedef struct _HIDP_CAPS {
	USAGE Usage;
	USAGE UsagePage;
	USHORT InputReportByteLength;
	USHORT OutputReportByteLength;
	USHORT FeatureReportByteLength;
	USHORT Reserved[17];
	USHORT fields_not_used_by_hidapi[10];
} HIDP_CAPS, *PHIDP_CAPS;

typedef void* PHIDP_PREPARSED_DATA;
#define HIDP_STATUS_SUCCESS 0x110000

typedef BOOLEAN(__stdcall *HidD_GetAttributes_)(HANDLE device, PHIDD_ATTRIBUTES attrib);
typedef BOOLEAN(__stdcall *HidD_GetSerialNumberString_)(HANDLE device, PVOID buffer, ULONG buffer_len);
typedef BOOLEAN(__stdcall *HidD_GetManufacturerString_)(HANDLE handle, PVOID buffer, ULONG buffer_len);
typedef BOOLEAN(__stdcall *HidD_GetProductString_)(HANDLE handle, PVOID buffer, ULONG buffer_len);
typedef BOOLEAN(__stdcall *HidD_SetFeature_)(HANDLE handle, PVOID data, ULONG length);
typedef BOOLEAN(__stdcall *HidD_GetFeature_)(HANDLE handle, PVOID data, ULONG length);
typedef BOOLEAN(__stdcall *HidD_GetIndexedString_)(HANDLE handle, ULONG string_index, PVOID buffer, ULONG buffer_len);
typedef BOOLEAN(__stdcall *HidD_GetPreparsedData_)(HANDLE handle, PHIDP_PREPARSED_DATA *preparsed_data);
typedef BOOLEAN(__stdcall *HidD_FreePreparsedData_)(PHIDP_PREPARSED_DATA preparsed_data);
typedef NTSTATUS(__stdcall *HidP_GetCaps_)(PHIDP_PREPARSED_DATA preparsed_data, HIDP_CAPS *caps);
typedef BOOLEAN(__stdcall *HidD_SetNumInputBuffers_)(HANDLE handle, ULONG number_buffers);

static HidD_GetAttributes_ HidD_GetAttributes;
static HidD_GetSerialNumberString_ HidD_GetSerialNumberString;
static HidD_GetManufacturerString_ HidD_GetManufacturerString;
static HidD_GetProductString_ HidD_GetProductString;
static HidD_SetFeature_ HidD_SetFeature;
static HidD_GetFeature_ HidD_GetFeature;
static HidD_GetIndexedString_ HidD_GetIndexedString;
static HidD_GetPreparsedData_ HidD_GetPreparsedData;
static HidD_FreePreparsedData_ HidD_FreePreparsedData;
static HidP_GetCaps_ HidP_GetCaps;
static HidD_SetNumInputBuffers_ HidD_SetNumInputBuffers;

static HMODULE lib_handle = NULL;
static BOOLEAN initialized = FALSE;
#endif /* HIDAPI_USE_DDK */

struct hid_device_ {
	HANDLE device_handle;
	BOOL blocking;
	USHORT output_report_length;
	size_t input_report_length;
	void *last_error_str;
	wchar_t *error_String;
	DWORD last_error_num;
	BOOL read_pending;
	char *read_buf;
	OVERLAPPED ol;
};

const int timeout = 500;
const int ahid_device = 0;

// ------------------------------------------------------------------
class TusbReadThread : public TThread {

private:
	aHid* Owner;

protected:
	void __fastcall TusbReadThread::Execute(void);

public:

	__fastcall TusbReadThread::TusbReadThread(aHid* AOwner) : TThread(true) {
		Owner = AOwner;
		Priority = tpHigher;
		FreeOnTerminate = false;

		Resume();
	}
};

// ------------------------------------------------------------------
void __fastcall TusbReadThread::Execute(void) {
	NameThreadForDebugging(System::String(L"UsbReadThread"));
	// If you must call Application.ProcessMessages() directly,
	// then don't call it unless there are messages actually waiting
	// to be processed. You can use the Win32 API GetQueueStatus() function
	// to detect that condition, for example:
	while (!this->Terminated) {
		// Owner->hid_read();
		Synchronize(&Owner->hid_read);
		Application->ProcessMessages();
		// if( Owner->hid_read(this)==64)
		if (GetQueueStatus(QS_ALLINPUT) != 0) {
			Application->ProcessMessages();
		}
	}
}

// ------------------------------------------------------------------
aHid::aHid() {

	hid_t *first_hid = NULL;
	hid_t *last_hid = NULL;

	hid_t *_hid = NULL;
	hid_init();
	HID_device = NULL;
	deviceAttached = false;
	inputBuffer.reserve(64);
}

// ------------------------------------------------------------------
aHid::~aHid() {
	detachUsbDevice();
}
// ---------------------------------------------------------------------------

struct hid_device_info * aHid::hid_enumerate(void) {
	BOOL res;

	struct hid_device_info *root = NULL; /* return object */
	struct hid_device_info *cur_dev = NULL;

	/* Windows objects for interacting with the driver. */
	GUID InterfaceClassGuid = {0x4d1e55b2, 0xf16f, 0x11cf, {0x88, 0xcb, 0x00, 0x11, 0x11, 0x00, 0x00, 0x30}};

	SP_DEVINFO_DATA devinfo_data;
	SP_DEVICE_INTERFACE_DATA device_interface_data;

	SP_DEVICE_INTERFACE_DETAIL_DATA_A *device_interface_detail_data = NULL;
	HDEVINFO device_info_set = INVALID_HANDLE_VALUE;
	int device_index = 0;

	int i;

	// if (hid_init() < 0)
	// return NULL;

	/* Initialize the Windows objects. */
	memset(&devinfo_data, 0x0, sizeof(devinfo_data));
	devinfo_data.cbSize = sizeof(SP_DEVINFO_DATA);
	device_interface_data.cbSize = sizeof(SP_DEVICE_INTERFACE_DATA);

	/* Get information for all the devices belonging to the HID class. */
	device_info_set = SetupDiGetClassDevsA(&InterfaceClassGuid, NULL, NULL, DIGCF_PRESENT | DIGCF_DEVICEINTERFACE);

	/* Iterate over each device in the HID class, looking for the right one. */

	for (; ;) {
		HANDLE write_handle = INVALID_HANDLE_VALUE;
		DWORD required_size = 0;
		HIDD_ATTRIBUTES attrib;

		res = SetupDiEnumDeviceInterfaces(device_info_set, NULL, &InterfaceClassGuid, device_index, &device_interface_data);

		if (!res) {
			/* A return of FALSE from this function means that
			 there are no more devices. */
			break;
		}

		/* Call with 0-sized detail size, and let the function
		 tell us how long the detail struct needs to be. The
		 size is put in &required_size. */
		res = SetupDiGetDeviceInterfaceDetailA(device_info_set, &device_interface_data, NULL, 0, &required_size, NULL);

		/* Allocate a long enough structure for device_interface_detail_data. */
		device_interface_detail_data = (SP_DEVICE_INTERFACE_DETAIL_DATA_A*) malloc(required_size);
		device_interface_detail_data->cbSize = sizeof(SP_DEVICE_INTERFACE_DETAIL_DATA_A);

		/* Get the detailed data for this device. The detail data gives us
		 the device path for this device, which is then passed into
		 CreateFile() to get a handle to the device. */
		res = SetupDiGetDeviceInterfaceDetailA(device_info_set, &device_interface_data, device_interface_detail_data,
			required_size, NULL, NULL);

		if (!res) {
			register_error(HID_device, L"Unable to call SetupDiGetDeviceInterfaceDetail");
			// Continue to the next device. */
			goto cont;
		}

		/* Make sure this device is of Setup Class "HIDClass" and has a
		 driver bound to it. */
		for (i = 0; ; i++) {
			char driver_name[256];

			/* Populate devinfo_data. This function will return failure
			 when there are no more interfaces left. */
			res = SetupDiEnumDeviceInfo(device_info_set, i, &devinfo_data);
			if (!res)
				goto cont;

			res = SetupDiGetDeviceRegistryPropertyA(device_info_set, &devinfo_data, SPDRP_CLASS, NULL, (PBYTE)driver_name,
				sizeof(driver_name), NULL);
			if (!res)
				goto cont;

			if (strcmp(driver_name, "HIDClass") == 0) {
				/* See if there's a driver bound. */
				res = SetupDiGetDeviceRegistryPropertyA(device_info_set, &devinfo_data, SPDRP_DRIVER, NULL, (PBYTE)driver_name,
					sizeof(driver_name), NULL);
				if (res)
					break;
			}
		}

		// wprintf(L"HandleName: %s\n", device_interface_detail_data->DevicePath);

		/* Open a handle to the device */
		write_handle = open_device(device_interface_detail_data->DevicePath, TRUE);

		/* Check validity of write_handle. */
		if (write_handle == INVALID_HANDLE_VALUE) {
			/* Unable to open the device. */
			register_error(HID_device, L"CreateFile");
			goto cont_close;
		}

		/* Get the Vendor ID and Product ID for this device. */
		attrib.Size = sizeof(HIDD_ATTRIBUTES);
		HidD_GetAttributes(write_handle, &attrib);
		// wprintf(L"Product/Vendor: %x %x\n", attrib.ProductID, attrib.VendorID);

		/* Check the VID/PID to see if we should add this
		 device to the enumeration list. */
		if ((_vendor_id == 0x0 || attrib.VendorID == _vendor_id) && (_product_id == 0x0 || attrib.ProductID == _product_id)) {

#define WSTR_LEN 512
			const char *str;
			struct hid_device_info *tmp;
			PHIDP_PREPARSED_DATA pp_data = NULL;
			HIDP_CAPS caps;
			BOOLEAN res;
			NTSTATUS nt_res;
			wchar_t wstr[WSTR_LEN]; /* TODO: Determine Size */
			size_t len;

			/* VID/PID match. Create the record. */
			tmp = (struct hid_device_info*) calloc(1, sizeof(struct hid_device_info));
			if (cur_dev) {
				cur_dev->next = tmp;
			}
			else {
				root = tmp;
			}
			cur_dev = tmp;

			/* Get the Usage Page and Usage for this device. */
			res = HidD_GetPreparsedData(write_handle, &pp_data);
			if (res) {
				nt_res = HidP_GetCaps(pp_data, &caps);
				if (nt_res == HIDP_STATUS_SUCCESS) {
					cur_dev->usage_page = caps.UsagePage;
					cur_dev->usage = caps.Usage;
				}

				HidD_FreePreparsedData(pp_data);
			}

			/* Fill out the record */
			cur_dev->next = NULL;
			str = device_interface_detail_data->DevicePath;
			if (str) {
				len = strlen(str);
				cur_dev->path = (char*) calloc(len + 1, sizeof(char));
				strncpy(cur_dev->path, str, len + 1);
				cur_dev->path[len] = '\0';
			}
			else
				cur_dev->path = NULL;

			/* Serial Number */
			res = HidD_GetSerialNumberString(write_handle, wstr, sizeof(wstr));
			wstr[WSTR_LEN - 1] = 0x0000;
			if (res) {
				cur_dev->serial_number = _wcsdup(wstr);
			}

			/* Manufacturer String */
			res = HidD_GetManufacturerString(write_handle, wstr, sizeof(wstr));
			wstr[WSTR_LEN - 1] = 0x0000;
			if (res) {
				cur_dev->manufacturer_string = _wcsdup(wstr);
			}

			/* Product String */
			res = HidD_GetProductString(write_handle, wstr, sizeof(wstr));
			wstr[WSTR_LEN - 1] = 0x0000;
			if (res) {
				cur_dev->product_string = _wcsdup(wstr);
			}

			/* VID/PID */
			cur_dev->vendor_id = attrib.VendorID;
			cur_dev->product_id = attrib.ProductID;

			/* Release Number */
			cur_dev->release_number = attrib.VersionNumber;

			/* Interface Number. It can sometimes be parsed out of the path
			 on Windows if a device has multiple interfaces. See
			 http://msdn.microsoft.com/en-us/windows/hardware/gg487473 or
			 search for "Hardware IDs for HID Devices" at MSDN. If it's not
			 in the path, it's set to -1. */
			cur_dev->interface_number = -1;
			if (cur_dev->path) {
				char *interface_component = strstr(cur_dev->path, "&mi_");
				if (interface_component) {
					char *hex_str = interface_component + 4;
					char *endptr = NULL;
					cur_dev->interface_number = strtol(hex_str, &endptr, 16);
					if (endptr == hex_str) {
						/* The parsing failed. Set interface_number to -1. */
						cur_dev->interface_number = -1;
					}
				}
			}
		}

	cont_close:
		CloseHandle(write_handle);
	cont:
		/* We no longer need the detail data. It can be freed */
		free(device_interface_detail_data);

		device_index++;

	}

	/* Close the device information handle. */
	SetupDiDestroyDeviceInfoList(device_info_set);

	return root;

}

// ---------------------------------------------------------------------------
bool aHid::hid_find(void) {
	/* TODO: Merge this functions with the Linux version. This function should be platform independent. */

	struct hid_device_info *devs, *cur_dev;
	const char *path_to_open = NULL;
	bool device_found = false;
	// circ_buff.clear();
	detachUsbDevice();
	// If the device is currently flagged as attached then we are 'rechecking' the device, probably
	// due to some message receieved from Windows indicating a device status chanage.  In this case
	// we should detach the USB device cleanly (if required) before reattaching it.

	devs = hid_enumerate();
	cur_dev = devs;
	while (cur_dev) {
		if (cur_dev->vendor_id == _vendor_id && cur_dev->product_id == _product_id) {

			if (_usage_page > 0 && _usage > 0) {
				if (_usage_page == cur_dev->usage_page && _usage == cur_dev->usage) {
					path_to_open = cur_dev->path;
					break;
				}
			}
			else {
				path_to_open = cur_dev->path;
				break;
			}
		}
		cur_dev = cur_dev->next;
	}

	if (path_to_open) {
		/* Open the device */
		HID_device = hid_open_path(path_to_open);
		hid_set_nonblocking(1);
		// writeHandle = hid_open_path(path_to_open);
		device_found = true;
		deviceAttached = true;
		usbReadThread = new TusbReadThread(this);

	}

	hid_free_enumeration(devs);

	return device_found;
}

// ---------------------------------------------------------------------------

HANDLE aHid::open_device(const char *path, BOOL enumerate) {
	HANDLE handle;
	DWORD desired_access = (enumerate) ? 0 : (GENERIC_WRITE | GENERIC_READ);
	DWORD share_mode = FILE_SHARE_READ | FILE_SHARE_WRITE;

	handle = CreateFileA(path, desired_access, share_mode, NULL, OPEN_EXISTING, FILE_FLAG_OVERLAPPED,
		/* FILE_ATTRIBUTE_NORMAL, */ 0);

	return handle;
}

// ---------------------------------------------------------------------------

HANDLE aHid::open_write_device(const char *path, BOOL enumerate) {
	HANDLE handle;
	DWORD desired_access = (enumerate) ? 0 : (GENERIC_WRITE | GENERIC_READ);
	DWORD share_mode = FILE_SHARE_READ | FILE_SHARE_WRITE;

	handle = CreateFileA(path, desired_access, share_mode, NULL, OPEN_EXISTING, FILE_FLAG_OVERLAPPED,
		/* FILE_ATTRIBUTE_NORMAL, */ 0);

	return handle;
}

// ---------------------------------------------------------------------------
int aHid::hid_init(void) {
#ifndef HIDAPI_USE_DDK
	if (!initialized) {
		if (lookup_functions() < 0) {
			hid_exit();
			return -1;
		}
		initialized = TRUE;
	}
#endif
	return 0;
}

// ---------------------------------------------------------------------------

int aHid::hid_exit(void) {
#ifndef HIDAPI_USE_DDK
	if (lib_handle)
		FreeLibrary(lib_handle);
	lib_handle = NULL;
	initialized = FALSE;
#endif
	return 0;
}

// ---------------------------------------------------------------------------
#ifndef HIDAPI_USE_DDK

int aHid::lookup_functions() {
	lib_handle = LoadLibraryA("hid.dll");
	if (lib_handle) {
#define RESOLVE(x) x = (x##_)GetProcAddress(lib_handle, #x); if (!x) return -1;
		RESOLVE(HidD_GetAttributes);
		RESOLVE(HidD_GetSerialNumberString);
		RESOLVE(HidD_GetManufacturerString);
		RESOLVE(HidD_GetProductString);
		RESOLVE(HidD_SetFeature);
		RESOLVE(HidD_GetFeature);
		RESOLVE(HidD_GetIndexedString);
		RESOLVE(HidD_GetPreparsedData);
		RESOLVE(HidD_FreePreparsedData);
		RESOLVE(HidP_GetCaps);
		RESOLVE(HidD_SetNumInputBuffers);
#undef RESOLVE
	}
	else
		return -1;

	return 0;
}
#endif

// ---------------------------------------------------------------------------
hid_device * aHid::hid_open_path(const char *path) {
	hid_device *dev;
	HIDP_CAPS caps;
	PHIDP_PREPARSED_DATA pp_data = NULL;
	BOOLEAN res;
	NTSTATUS nt_res;

	if (hid_init() < 0) {
		return NULL;
	}

	dev = new_hid_device();

	/* Open a handle to the device */
	dev->device_handle = open_device(path, FALSE);

	/* Check validity of write_handle. */
	if (dev->device_handle == INVALID_HANDLE_VALUE) {
		/* Unable to open the device. */
		register_error(dev, L"hid_open_path");
		goto err;
	}

	/* Set the Input Report buffer size to 64 reports. */
	res = HidD_SetNumInputBuffers(dev->device_handle, 64);
	if (!res) {
		register_error(dev, L"HidD_SetNumInputBuffers");
		goto err;
	}

	/* Get the Input Report length for the device. */
	res = HidD_GetPreparsedData(dev->device_handle, &pp_data);
	if (!res) {
		register_error(dev, L"HidD_GetPreparsedData");
		goto err;
	}
	nt_res = HidP_GetCaps(pp_data, &caps);
	if (nt_res != HIDP_STATUS_SUCCESS) {
		register_error(dev, L"HidP_GetCaps");
		goto err_pp_data;
	}
	dev->output_report_length = caps.OutputReportByteLength;
	dev->input_report_length = caps.InputReportByteLength;
	HidD_FreePreparsedData(pp_data);

	dev->read_buf = (char*) malloc(dev->input_report_length);

	return dev;

err_pp_data:
	HidD_FreePreparsedData(pp_data);
err:
	free_hid_device(dev);
	return NULL;
}

// ---------------------------------------------------------------------------
hid_device *aHid::new_hid_device() {

	hid_device *dev = (hid_device*) calloc(1, sizeof(hid_device));
	dev->device_handle = INVALID_HANDLE_VALUE;
	dev->blocking = 1;
	dev->output_report_length = 0;
	dev->input_report_length = 0;
	dev->last_error_str = NULL;
	dev->last_error_num = 0;
	dev->read_pending = FALSE;
	dev->read_buf = NULL;
	memset(&dev->ol, 0, sizeof(dev->ol));
	dev->ol.hEvent = CreateEvent(NULL, FALSE, FALSE /* initial state f=nonsignaled */ , NULL);

	return dev;
}

// ---------------------------------------------------------------------------
void aHid::register_error(hid_device *device, const wchar_t *op) {
	WCHAR *msg;

	DEBUG_MESSAGE(L"ERROR HERE");

	DEBUG_MESSAGE(op);

	FormatMessageW(FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS, NULL,
		GetLastError(), MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT), (LPWSTR)&msg, 0 /* sz */ , NULL);

	/* Store the message off in the Device entry so that
	 the hid_error() function can pick it up. */
	LocalFree(device->last_error_str);
	device->last_error_str = msg;
	device->error_String = msg;
	DEBUG_MESSAGE(msg);

}

// ---------------------------------------------------------------------------
void aHid::free_hid_device(hid_device *dev) {
	CloseHandle(dev->ol.hEvent);
	CloseHandle(dev->device_handle);
	LocalFree(dev->last_error_str);
	free(dev->read_buf);
	free(dev);
}

// ---------------------------------------------------------------------------
void aHid::hid_free_enumeration(struct hid_device_info *devs) {
	/* TODO: Merge this with the Linux version. This function is platform-independent. */
	struct hid_device_info *d = devs;
	while (d) {
		struct hid_device_info *next = d->next;
		free(d->path);
		free(d->serial_number);
		free(d->manufacturer_string);
		free(d->product_string);
		free(d);
		d = next;
	}
}

// ---------------------------------------------------------------------------
int aHid::hid_get_manufacturer_string(wchar_t *string, size_t maxlen) {
	BOOL res;
	if (HID_device == NULL)
		return -1;

	res = HidD_GetManufacturerString(HID_device->device_handle, string, sizeof(wchar_t) * MIN(maxlen, MAX_STRING_WCHARS));
	if (!res) {
		register_error(HID_device, L"HidD_GetManufacturerString");
		return -1;
	}

	return 0;
}

// ---------------------------------------------------------------------------
int aHid::hid_get_product_string(wchar_t *string, size_t maxlen) {
	BOOL res;
	if (HID_device == NULL)
		return -1;

	res = HidD_GetProductString(HID_device->device_handle, string, sizeof(wchar_t) * MIN(maxlen, MAX_STRING_WCHARS));
	if (!res) {
		register_error(HID_device, L"HidD_GetProductString");
		return -1;
	}

	return 0;
}

// ---------------------------------------------------------------------------
int aHid::hid_write(unsigned char *data, size_t length) {
	if (HID_device == NULL)
		return -1;

	DWORD bytes_written;
	BOOL res;

	OVERLAPPED ol;
	unsigned char *buf;
	memset(&ol, 0, sizeof(ol));

	/* Make sure the right number of bytes are passed to WriteFile. Windows
	 expects the number of bytes which are in the _longest_ report (plus
	 one for the report number) bytes even if the data is a report
	 which is shorter than that. Windows gives us this value in
	 caps.OutputReportByteLength. If a user passes in fewer bytes than this,
	 create a temporary buffer which is the proper size. */
	if (length >= HID_device->output_report_length) {
		/* The user passed the right number of bytes. Use the buffer as-is. */
		buf = (unsigned char *) data;
	}
	else {
		/* Create a temporary buffer and copy the user's data
		 into it, padding the rest with zeros. */
		buf = (unsigned char *) malloc(HID_device->output_report_length);
		memcpy(buf, data, length);
		memset(buf + length, 0, HID_device->output_report_length - length);
		length = HID_device->output_report_length;
	}
	//
	res = WriteFile(HID_device->device_handle, buf, length, NULL, &ol);

	if (!res) {
		if (GetLastError() != ERROR_IO_PENDING) {
			// On any write error signalled asynchronously, we assume
			// that the port has disconnected.
			//
			// detachUsbDevice();
			/* WriteFile() failed. Return error. */
			register_error(HID_device, L"WriteFile() failed. Return error.");
			bytes_written = -1;
			goto end_of_function;
		}
	}

	/* Wait here until the write is done. This makes
	 hid_write() synchronous. */
	res = GetOverlappedResult(HID_device->device_handle, &ol, &bytes_written, TRUE /* wait */);
	if (!res) {
		/* The Write operation failed. */
		register_error(HID_device, L"The Write operation failed");
		bytes_written = -1;
		goto end_of_function;
	}

end_of_function:
	if (buf != data)
		free(buf);

	return bytes_written;
}

// ---------------------------------------------------------------------------
int aHid::hid_read_timeout(hid_device *dev, unsigned char *data, size_t length, int milliseconds) {
	DWORD bytes_read = 0;
	size_t copy_len = 0;
	BOOL res;

	/* Copy the handle for convenience. */
	HANDLE ev = dev->ol.hEvent;

	if (!dev->read_pending) {
		/* Start an Overlapped I/O read. */
		dev->read_pending = TRUE;
		memset(dev->read_buf, 0, dev->input_report_length);
		// EnterCriticalSection(&rx_mutex);
		ResetEvent(ev);
		res = ReadFile(dev->device_handle, dev->read_buf, dev->input_report_length, &bytes_read, &dev->ol);
		// LeaveCriticalSection(&rx_mutex);
		if (!res) {
			if (GetLastError() != ERROR_IO_PENDING) {
				/* ReadFile() has failed.
				 Clean up and return error. */
				CancelIo(dev->device_handle);
				dev->read_pending = FALSE;
				goto end_of_function;
			}
		}

	}

	if (milliseconds >= 0) {
		/* See if there is any data yet. */
		res = WaitForSingleObject(ev, milliseconds);
		if (res != WAIT_OBJECT_0) {
			/* There was no data this time. Return zero bytes available,
			 but leave the Overlapped I/O running. */
			return 0;
		}
	}

	/* Either WaitForSingleObject() told us that ReadFile has completed, or
	 we are in non-blocking mode. Get the number of bytes read. The actual
	 data has been copied to the data[] array which was passed to ReadFile(). */
	res = GetOverlappedResult(dev->device_handle, &dev->ol, &bytes_read, TRUE /* wait */);

	/* Set pending back to false, even if GetOverlappedResult() returned error. */
	dev->read_pending = FALSE;

	if (res && bytes_read > 0) {
		if (dev->read_buf[0] == 0x0) {
			/* If report numbers aren't being used, but Windows sticks a report
			 number (0x0) on the beginning of the report anyway. To make this
			 work like the other platforms, and to make it work more like the
			 HID spec, we'll skip over this byte. */
			bytes_read--;
			copy_len = length > bytes_read ? bytes_read : length;
			memcpy(data, dev->read_buf + 1, copy_len);
		}
		else {
			/* Copy the whole buffer, report number and all. */
			copy_len = length > bytes_read ? bytes_read : length;
			memcpy(data, dev->read_buf, copy_len);
		}
	}

end_of_function:
	if (!res) {
		// On any read error signalled asynchronously, we assume
		// that the scope has disconnected.
		//
		// detachUsbDevice();
		register_error(dev, L"GetOverlappedResult");
		return -1;
	}

	return copy_len;
}

// ---------------------------------------------------------------------------
/** @brief Read an Input report from a HID device.

 Input reports are returned
 to the host through the INTERRUPT IN endpoint. The first byte will
 contain the Report number if the device uses numbered reports.


 @returns
 This function returns the actual number of bytes read and
 -1 on error. If no packet was available to be read and
 the handle is in non-blocking mode, this function returns 0.
 */
void __fastcall aHid::hid_read(void) {

	if (HID_device == NULL)
		return;

	unsigned int R = hid_read_timeout(HID_device, reinterpret_cast<char*>(&(inputBuffer[0])), HID_device->input_report_length,
		(HID_device->blocking) ? -1 : 0);
	if (R == 64) {

		callBack(reinterpret_cast<uint16_t*>(&(inputBuffer[0])));
	}
	return;
}

// ---------------------------------------------------------------------------
/** @brief Set the device handle to be non-blocking.

 In non-blocking mode calls to hid_read() will return
 immediately with a value of 0 if there is no data to be
 read. In blocking mode, hid_read() will wait (block) until
 there is data to read before returning.

 Nonblocking can be turned on and off at any time.

 @ingroup API
 @param device A device handle returned from hid_open().
 @param nonblock enable or not the nonblocking reads
 - 1 to enable nonblocking
 - 0 to disable nonblocking.

 @returns
 This function returns 0 on success and -1 on error.
 */
int aHid::hid_set_nonblocking(int nonblock) {
	HID_device->blocking = !nonblock;
	return 0; /* Success */
}

// ---------------------------------------------------------------------------

// This public method filters WndProc notification messages for the required
// device notifications and triggers a re-detection of the USB device if required.
//
// The main form of the application needs to include an override of the WndProc
// class for this to be called, usually this is defined as a protected method
// of the main form and looks like the following:
//
// protected: virtual void WndProc(Message% m) override
// {
// a_usbHidCommunication.handleDeviceChangeMessages(m, vid, pid);
// Form::WndProc( m ); // Call the original method
// } // END WndProc method
//
void aHid::handleDeviceChangeMessages(TMessage &m) {
	if (m.Msg == WM_DEVICECHANGE) {
		if (((int)m.WParam == DBT_DEVICEARRIVAL) || ((int)m.WParam == DBT_DEVICEREMOVEPENDING) ||
			((int)m.WParam == DBT_DEVICEREMOVECOMPLETE) || ((int)m.WParam == DBT_CONFIGCHANGED) ||
			((int)m.WParam == DBT_DEVNODES_CHANGED)) {
			// Check the device is still available
			hid_find(); // VID, PID
		}
	}
}

// ---------------------------------------------------------------------------
// This public method detaches the USB device and forces the
// worker threads to cancel IO and abort if required.
// This is used when we're done communicating with the device
void aHid::detachUsbDevice(void) {

	try {
		if (!usbReadThread->Finished) {

			// Cancel any pending IO operations
			CancelIoEx(HID_device, NULL);
			usbReadThread->Terminate();
			usbReadThread->WaitFor();

			deviceAttached = false;

			if (HID_device->device_handle != NULL) {
				CloseHandle(HID_device->device_handle);
			}

		}
	}

	catch (...) {
	}
} // END detachUsbDevice Method

// ------------------------------------------------------------------

bool __fastcall aHid::isDataAvailable(void) {
	// return (!circ_buff.empty());
}

// ----------------------------------------------------------------
wchar_t * __fastcall aHid::getError(void) {
	if (HID_device != NULL)
		return HID_device->error_String;
	else
		return L"OK";
}

// ----------------------------------------------------------------
// rawhid_open - open 1 or more devices
//
// Inputs:
// max = maximum number of devices to open
// vid = Vendor ID, or -1 if any
// pid = Product ID, or -1 if any
// usage_page = top level usage page, or -1 if any
// usage = top level usage number, or -1 if any
// Output:
// actual number of devices opened
//
int __fastcall aHid::rawhid_open(int max, int vid, int pid, int usage_page, int usage) {

	GUID InterfaceClassGuid = {0x4d1e55b2, 0xf16f, 0x11cf, {0x88, 0xcb, 0x00, 0x11, 0x11, 0x00, 0x00, 0x30}};

	SP_DEVICE_INTERFACE_DATA device_interface_data;

	SP_DEVICE_INTERFACE_DETAIL_DATA_A *device_interface_detail_data = NULL;
	HDEVINFO device_info_set = INVALID_HANDLE_VALUE;
	DWORD index = 0, required_size;
	HIDD_ATTRIBUTES attrib;
	HANDLE write_handle = INVALID_HANDLE_VALUE;

	PHIDP_PREPARSED_DATA hid_data;
	HIDP_CAPS capabilities;

	BOOL ret;
	hid_t *hid;
	int count = 0;

	if (first_hid)
		free_all_hid();
	if (max < 1)
		return 0;
	if (!rx_event) {
		rx_event = CreateEvent(NULL, TRUE, TRUE, NULL);
		tx_event = CreateEvent(NULL, TRUE, TRUE, NULL);
		InitializeCriticalSection(&rx_mutex);
		InitializeCriticalSection(&tx_mutex);
	}

	/* Initialize the Windows objects. */
	device_interface_data.cbSize = sizeof(SP_DEVICE_INTERFACE_DATA);

	device_info_set = SetupDiGetClassDevsA(&InterfaceClassGuid, NULL, NULL, DIGCF_PRESENT | DIGCF_DEVICEINTERFACE);
	if (device_info_set == INVALID_HANDLE_VALUE)
		return 0;

	for (index = 0; 1; index++) {

		ret = SetupDiEnumDeviceInterfaces(device_info_set, NULL, &InterfaceClassGuid, index, &device_interface_data);
		if (!ret) {
			DWORD dw = GetLastError();
			return count;
		}

		SetupDiGetDeviceInterfaceDetailA(device_info_set, &device_interface_data, NULL, 0, &required_size, NULL);

		/* Allocate a long enough structure for device_interface_detail_data. */
		device_interface_detail_data = (SP_DEVICE_INTERFACE_DETAIL_DATA_A*) malloc(required_size);
		device_interface_detail_data->cbSize = sizeof(SP_DEVICE_INTERFACE_DETAIL_DATA_A);

		if (device_interface_detail_data == NULL)
			continue;

		ret = SetupDiGetDeviceInterfaceDetailA(device_info_set, &device_interface_data, device_interface_detail_data,
			required_size, NULL, NULL);
		if (!ret) {
			DWORD dw = GetLastError();
			free(device_interface_detail_data);
			continue;
		}
		write_handle = CreateFileA(device_interface_detail_data->DevicePath, GENERIC_READ | GENERIC_WRITE,
			FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_EXISTING, FILE_FLAG_OVERLAPPED, 0);
		free(device_interface_detail_data);
		if (write_handle == INVALID_HANDLE_VALUE)
			continue;
		attrib.Size = sizeof(HIDD_ATTRIBUTES);
		ret = HidD_GetAttributes(write_handle, &attrib);
		// printf("vid: %4x\n", attrib.VendorID);
		if (!ret || (vid > 0 && attrib.VendorID != vid) || (pid > 0 && attrib.ProductID != pid) ||
			!HidD_GetPreparsedData(write_handle, &hid_data)) {
			CloseHandle(write_handle);
			continue;
		}
		if (!HidP_GetCaps(hid_data, &capabilities) || (usage_page > 0 && capabilities.UsagePage != usage_page) ||
			(usage > 0 && capabilities.Usage != usage)) {
			HidD_FreePreparsedData(hid_data);
			CloseHandle(write_handle);
			continue;
		}
		HidD_FreePreparsedData(hid_data);
		hid = (struct hid_struct*)malloc(sizeof(struct hid_struct));
		if (!hid) {
			CloseHandle(write_handle);
			continue;
		}
		hid->handle = write_handle;
		hid->open = 1;
		add_hid(hid);
		count++;
		if (count >= max)
			return count;
	}
	return count;
}

// ----------------------------------------------------------------------------------------
void __fastcall aHid::add_hid(hid_t *h) {
	if (!first_hid || !last_hid) {
		first_hid = last_hid = h;
		h->next = h->prev = NULL;
		return;
	}
	last_hid->next = h;
	h->prev = last_hid;
	h->next = NULL;
	last_hid = h;
}

// ----------------------------------------------------------------------------------------
int __fastcall aHid::hid_sendAck(void) {
	// return rawhid_send(ahid_device, buf, sizeof(buf), timeout);
}

// ----------------------------------------------------------------------------------------
int __fastcall aHid::hid_checkAck(uint8_t *buf) {
	char buf2[BUFFER_SIZE];
	int n;
	n = rawhid_recv(ahid_device, buf2, sizeof(buf2), timeout);
	if (n < 1)
		return -1;
	n = memcmp(buf, buf2, sizeof(buf));
		if (n) {
		return -1;
	}
	return 1;
}

// ----------------------------------------------------------------------------------------
int __fastcall aHid::hid_sendWithAck(uint8_t *buf, int len) {
	char buf2[BUFFER_SIZE];
	int retVal = 1;
	int n;
	n = rawhid_send(ahid_device, buf, len, timeout);

	if (n < 1) {
		retVal = -1;
	}
	n = rawhid_recv(ahid_device, buf2, len, timeout*2);
	if (n < 1) {
		retVal = -1;
	}
	n = memcmp(buf, buf2, len);
	if (n) {
		retVal = -1;
	}
	return retVal;
}

// ----------------------------------------------------------------------------------------
int __fastcall aHid::hid_rcvWithAck(uint8_t *buf, int len) {
	int n;
	int retVal = 1;
	n = rawhid_recv(ahid_device, buf, len, timeout);
	if (n < 1) {
			retVal = -1;
	}
	n = rawhid_send(ahid_device, buf, len, timeout);
	if (n < 1) {

		retVal = -1;
	}
	return retVal;

}
// ----------------------------------------------------------------------------------------

int __fastcall aHid::hid_rcv(uint8_t *buf, int len) {
	int n;
	int retVal = 1;
	n = rawhid_recv(ahid_device, buf, len, timeout);
	if (n < 1) {
			retVal = -1;
	}

	return retVal;

}
// ----------------------------------------------------------------------------------------
  int __fastcall aHid::hid_send(uint8_t *buf, int len) {
	int retVal = 1;
	int n;
	n = rawhid_send(ahid_device, buf, len, timeout);

	if (n < 1) {
		retVal = -1;
	}

	return retVal;
}


// ----------------------------------------------------------------------------------------
// rawhid_send - send a packet
// Inputs:
// num = device to transmit to (zero based)
// buf = buffer containing packet to send
// len = number of bytes to transmit
// timeout = time to wait, in milliseconds
// Output:
// number of bytes sent, or -1 on error
//
int __fastcall aHid::rawhid_send(int num, uint8_t *buf, int len, int timeout) {
	hid_t *hid;
	unsigned char tmpbuf[516];
	OVERLAPPED ov;
	DWORD n, r;

	if (sizeof(tmpbuf) < len + 1)
		return -1;
	hid = get_hid(num);
	if (!hid || !hid->open)
		return -1;
	EnterCriticalSection(&tx_mutex);
	ResetEvent(&tx_event);
	memset(&ov, 0, sizeof(ov));
	ov.hEvent = tx_event;
	tmpbuf[0] = 0;
	memcpy(tmpbuf + 1, buf, len);
	if (!WriteFile(hid->handle, tmpbuf, len + 1, NULL, &ov)) {
		if (GetLastError() != ERROR_IO_PENDING)
			goto return_error;
		r = WaitForSingleObject(tx_event, timeout);
		if (r == WAIT_TIMEOUT)
			goto return_timeout;
		if (r != WAIT_OBJECT_0)
			goto return_error;
	}
	if (!GetOverlappedResult(hid->handle, &ov, &n, FALSE))
		goto return_error;
	LeaveCriticalSection(&tx_mutex);
	if (n <= 0)
		return -1;
	return n - 1;
return_timeout:
	CancelIo(hid->handle);
	LeaveCriticalSection(&tx_mutex);
	return 0;
return_error:
	print_win32_err();
	LeaveCriticalSection(&tx_mutex);
	return -1;
}

// ----------------------------------------------------------------------------------------
// rawhid_recv - receive a packet
// Inputs:
// num = device to receive from (zero based)
// buf = buffer to receive packet
// len = buffer's size
// timeout = time to wait, in milliseconds
// Output:
// number of bytes received, or -1 on error
//
int __fastcall aHid::rawhid_recv(int num, uint8_t *buf, int len, int timeout) {
	hid_t *hid;
	unsigned char tmpbuf[516];
	OVERLAPPED ov;
	DWORD n, r;

	if (sizeof(tmpbuf) < len + 1)
		return -1;
	hid = get_hid(num);
	if (!hid || !hid->open)
		return -1;
	EnterCriticalSection(&rx_mutex);
	ResetEvent(&rx_event);
	memset(&ov, 0, sizeof(ov));
	ov.hEvent = rx_event;
	if (!ReadFile(hid->handle, tmpbuf, len + 1, NULL, &ov)) {
		if (GetLastError() != ERROR_IO_PENDING)
			goto return_error;
		r = WaitForSingleObject(rx_event, timeout);
		if (r == WAIT_TIMEOUT)
			goto return_timeout;
		if (r != WAIT_OBJECT_0)
			goto return_error;
	}
	if (!GetOverlappedResult(hid->handle, &ov, &n, FALSE))
		goto return_error;
	LeaveCriticalSection(&rx_mutex);
	if (n <= 0)
		return -1;
	n--;
	if (n > len)
		n = len;
	memcpy(buf, tmpbuf + 1, n);
	return n;
return_timeout:
	CancelIo(hid->handle);
	LeaveCriticalSection(&rx_mutex);
	return 0;
return_error:
	print_win32_err();
	LeaveCriticalSection(&rx_mutex);
	return -1;
}

hid_t * __fastcall aHid::get_hid(int num) {
	hid_t *p;
	for (p = first_hid; p && num > 0; p = p->next, num--);
	return p;
}

// ----------------------------------------------------------------------------------------
void __fastcall aHid::print_win32_err(void) {
	wchar_t buf[256];
	wchar_t buff[256];
	DWORD err;

	err = GetLastError();
	FormatMessage(FORMAT_MESSAGE_FROM_SYSTEM, NULL, err, 0, buf, sizeof(buf), NULL);
	swprintf(buff, L"err %ld: %s\n", err, buf);
	OutputDebugStringW(buff);

}

// ----------------------------------------------------------------------------------------
void __fastcall aHid::free_all_hid(void) {
	hid_t *p, *q;

	for (p = first_hid; p; p = p->next) {
		hid_close(p);
	}
	p = first_hid;
	while (p) {
		q = p;
		p = p->next;
		free(q);
	}
	first_hid = last_hid = NULL;

}

// ----------------------------------------------------------------------------------------
void __fastcall aHid::hid_close(hid_t *hid) {
	CloseHandle(hid->handle);
	hid->handle = NULL;
}

// ----------------------------------------------------------------------------------------
bool __fastcall aHid::isConnected(void) {
	return (first_hid);

}
