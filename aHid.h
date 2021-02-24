/*
 * aHid.h
 *
 *  Created on: 30 Oct. 2019
 *      Author: apaml
 */

#ifndef AHID_H_
#define AHID_H_
#include <windows.h>
#include <wchar.h>
#include <vcl.h>
#include <vector>
using namespace std;

#ifdef _WIN32
#define HID_API_EXPORT __declspec(dllexport)
#define HID_API_CALL
#else
#define HID_API_EXPORT /**< API export macro */
#define HID_API_CALL /**< API call macro */
#endif

#define BUFFER_SIZE 64

#ifdef __cplusplus

extern "C" {
#endif
	struct hid_device_;
	typedef struct hid_device_ hid_device;
	/** < opaque hidapi structure */

	/** hidapi info structure */
	struct hid_device_info {
		/** Platform-specific device path */
		char *path;
		/** Device Vendor ID */
		unsigned short vendor_id;
		/** Device Product ID */
		unsigned short product_id;
		/** Serial Number */
		wchar_t *serial_number;
		/** Device Release Number in binary-coded decimal,
		 also known as Device Version Number */
		unsigned short release_number;
		/** Manufacturer String */
		wchar_t *manufacturer_string;
		/** Product string */
		wchar_t *product_string;
		/** Usage Page for this Device/Interface
		 (Windows/Mac only). */
		unsigned short usage_page;
		/** Usage for this Device/Interface
		 (Windows/Mac only). */
		unsigned short usage;
		/** The USB interface which this logical device
		 represents. Valid on both Linux implementations
		 in all cases, and valid on the Windows implementation
		 only if the device contains more than one interface. */
		int interface_number;

		/** Pointer to the next device */
		struct hid_device_info *next;
	};

#ifdef __cplusplus
}
#endif

typedef struct {
	uint16_t Command;
	uint16_t X;
	uint16_t Y;
	float data;
} rxData;

class TusbReadThread;
typedef struct hid_struct hid_t;

static HANDLE rx_event = NULL;
static HANDLE tx_event = NULL;
static CRITICAL_SECTION rx_mutex;
static CRITICAL_SECTION tx_mutex;

struct hid_struct {
	HANDLE handle;
	int open;
	struct hid_struct *prev;
	struct hid_struct *next;
};

class aHid {

public:
	aHid();
	virtual ~aHid();

	TusbReadThread *usbReadThread;

	void SetVendorID(unsigned short vendor_id) {
		_vendor_id = vendor_id;
	}

	void SetProductID(unsigned short product_id) {
		_product_id = product_id;
	}

	void SetUsagePage(unsigned short usage_page) {
		_usage_page = usage_page;
	}

	void SetPage(unsigned short usage) {
		_usage = usage;
	}

	wchar_t* __fastcall GetError(void) {
		return getError();
	}

	// Boolean isDeviceAttached(void) {
	// return deviceAttached;

	// }

	unsigned int getCircBuffReserve(void) {
		return cirBuffReserve;
	}

	void setCallback(void(*fPtr)(uint16_t *)) {
		callBack = fPtr;
	}

	void upDateData(void) {
		if (callBack == NULL)
			return;
		// callBack(getData());

	}

	void DetachUsbDevice(void) {

		detachUsbDevice();
	}

	bool hid_find(void);
	int hid_get_manufacturer_string(wchar_t *string, size_t maxlen);
	int hid_get_product_string(hid_device * device, wchar_t *string, size_t maxlen);
	int hid_get_product_string(wchar_t *string, size_t maxlen);
	int hid_write(uint8_t *data, size_t length);
	void __fastcall hid_read(void); // (TObject *Sender
	void handleDeviceChangeMessages(TMessage & Message);
	bool __fastcall isDataAvailable(void);
	wchar_t * __fastcall getError(void);
	int __fastcall rawhid_open(int max, int vid, int pid, int usage_page, int usage);
	void __fastcall add_hid(hid_t *h);
	int __fastcall hid_sendAck(void);
	int __fastcall hid_checkAck(uint8_t *buf);
	int __fastcall hid_sendWithAck(uint8_t *buf, int len);
	int __fastcall hid_send(uint8_t *buf, int len);
	int __fastcall hid_rcvWithAck(uint8_t *buf, int len);
    int __fastcall hid_rcv(uint8_t *buf, int len);
	int __fastcall rawhid_send(int num, uint8_t *buf, int len, int timeout);
	int __fastcall rawhid_recv(int num, uint8_t *buf, int len, int timeout);
	bool __fastcall isConnected(void);

private:

	BOOL res;
	Boolean deviceAttached;
	hid_device * HID_device;
	typedef struct hid_struct hid_t;

	hid_t * __fastcall get_hid(int num);
	void __fastcall print_win32_err(void);
	void __fastcall free_all_hid(void);

	hid_t *first_hid;
	hid_t *last_hid;

	// hid_t *_hid;

	void(*callBack)(uint16_t*);

	// ::boost::circular_buffer<rxData>circ_buff;

	unsigned int cirBuffReserve;

	// buffers for USB communication
	// int8_t inputBuffer[64];
	std::vector<int8_t>inputBuffer;

	unsigned short _vendor_id, _product_id, _usage_page, _usage;

	int hid_init(void);
	int hid_exit(void);
	struct hid_device_info HID_API_EXPORT * HID_API_CALL hid_enumerate(void);
	void hid_free_enumeration(struct hid_device_info * devs);
	hid_device * HID_API_CALL hid_open_path(const char *path);
	int hid_read_timeout(hid_device * dev, unsigned char *data, size_t length, int milliseconds);
	int hid_set_nonblocking(int nonblock);
	int hid_send_feature_report(hid_device * device, const unsigned char *data, size_t length);
	int hid_get_feature_report(hid_device * device, unsigned char *data, size_t length);
	void hid_close(hid_device * device);
	int hid_get_serial_number_string(hid_device * device, wchar_t *string, size_t maxlen);
	HANDLE open_device(const char *path, BOOL enumerate);
	HANDLE open_write_device(const char *path, BOOL enumerate);
	int lookup_functions();
	hid_device *new_hid_device();
	void register_error(hid_device * device, const wchar_t *op);
	void free_hid_device(hid_device * dev);
	int hid_get_indexed_string(hid_device * device, int string_index, wchar_t *string, size_t maxlen);
	const wchar_t* hid_error(hid_device * device);
	void detachUsbDevice(void);
	void __fastcall hid_close(hid_t *hid);

};

extern aHid Ahid;
#endif /* AHID_H_ */
