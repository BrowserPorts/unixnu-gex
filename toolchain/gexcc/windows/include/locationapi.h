/* locationapi.h (gexcc-win's compatibility headers): the Windows Location API's
 * interfaces, which Wine's headers lack, as the SDK and MinGW declare them (C++);
 * the GUIDs are defined here, uuid.lib's part */
#pragma once
#include <windows.h>
#include <propsys.h>

typedef GUID SENSOR_ID;

typedef enum LOCATION_REPORT_STATUS {
    REPORT_NOT_SUPPORTED = 0,
    REPORT_ERROR = 1,
    REPORT_ACCESS_DENIED = 2,
    REPORT_INITIALIZING = 3,
    REPORT_RUNNING = 4
} LOCATION_REPORT_STATUS;

typedef enum LOCATION_DESIRED_ACCURACY {
    LOCATION_DESIRED_ACCURACY_DEFAULT = 0,
    LOCATION_DESIRED_ACCURACY_HIGH = 1
} LOCATION_DESIRED_ACCURACY;

static const GUID IID_ILocationReport = { 0xc8b7f7ee, 0x75d0, 0x4db9, { 0xb6, 0x2d, 0x7a, 0x0f, 0x36, 0x9c, 0xa4, 0x56 } };
static const GUID IID_ILatLongReport = { 0x7fed806d, 0x0ef8, 0x4f07, { 0x80, 0xac, 0x36, 0xa0, 0xbe, 0xae, 0x31, 0x34 } };
static const GUID IID_ILocationEvents = { 0xcae02bbf, 0x798b, 0x4508, { 0xa2, 0x07, 0x35, 0xa7, 0x90, 0x6d, 0xc7, 0x3d } };
static const GUID IID_ILocation = { 0xab2ece69, 0x56d9, 0x4f28, { 0xb5, 0x25, 0xde, 0x1b, 0x0e, 0xe4, 0x42, 0x37 } };
static const GUID CLSID_Location = { 0xe5b8e079, 0xee6d, 0x4e33, { 0xa4, 0x38, 0xc8, 0x7f, 0x2e, 0x95, 0x92, 0x54 } };

#ifdef __cplusplus
MIDL_INTERFACE("c8b7f7ee-75d0-4db9-b62d-7a0f369ca456")
ILocationReport : public IUnknown
{
    virtual HRESULT STDMETHODCALLTYPE GetSensorID(SENSOR_ID *id) = 0;
    virtual HRESULT STDMETHODCALLTYPE GetTimestamp(SYSTEMTIME *time) = 0;
    virtual HRESULT STDMETHODCALLTYPE GetValue(REFPROPERTYKEY key, PROPVARIANT *value) = 0;
};

MIDL_INTERFACE("7fed806d-0ef8-4f07-80ac-36a0beae3134")
ILatLongReport : public ILocationReport
{
    virtual HRESULT STDMETHODCALLTYPE GetLatitude(DOUBLE *latitude) = 0;
    virtual HRESULT STDMETHODCALLTYPE GetLongitude(DOUBLE *longitude) = 0;
    virtual HRESULT STDMETHODCALLTYPE GetErrorRadius(DOUBLE *radius) = 0;
    virtual HRESULT STDMETHODCALLTYPE GetAltitude(DOUBLE *altitude) = 0;
    virtual HRESULT STDMETHODCALLTYPE GetAltitudeError(DOUBLE *error) = 0;
};

MIDL_INTERFACE("cae02bbf-798b-4508-a207-35a7906dc73d")
ILocationEvents : public IUnknown
{
    virtual HRESULT STDMETHODCALLTYPE OnLocationChanged(REFIID type, ILocationReport *report) = 0;
    virtual HRESULT STDMETHODCALLTYPE OnStatusChanged(REFIID type, LOCATION_REPORT_STATUS status) = 0;
};

MIDL_INTERFACE("ab2ece69-56d9-4f28-b525-de1b0ee44237")
ILocation : public IUnknown
{
    virtual HRESULT STDMETHODCALLTYPE RegisterForReport(ILocationEvents *events, REFIID type, DWORD interval) = 0;
    virtual HRESULT STDMETHODCALLTYPE UnregisterForReport(REFIID type) = 0;
    virtual HRESULT STDMETHODCALLTYPE GetReport(REFIID type, ILocationReport **report) = 0;
    virtual HRESULT STDMETHODCALLTYPE GetReportStatus(REFIID type, LOCATION_REPORT_STATUS *status) = 0;
    virtual HRESULT STDMETHODCALLTYPE GetReportInterval(REFIID type, DWORD *interval) = 0;
    virtual HRESULT STDMETHODCALLTYPE SetReportInterval(REFIID type, DWORD interval) = 0;
    virtual HRESULT STDMETHODCALLTYPE GetDesiredAccuracy(REFIID type, LOCATION_DESIRED_ACCURACY *accuracy) = 0;
    virtual HRESULT STDMETHODCALLTYPE SetDesiredAccuracy(REFIID type, LOCATION_DESIRED_ACCURACY accuracy) = 0;
    virtual HRESULT STDMETHODCALLTYPE RequestPermissions(HWND parent, IID *types, ULONG count, BOOL modal) = 0;
};

#ifdef __CRT_UUID_DECL
__CRT_UUID_DECL(ILocationReport, 0xc8b7f7ee, 0x75d0, 0x4db9, 0xb6, 0x2d, 0x7a, 0x0f, 0x36, 0x9c, 0xa4, 0x56)
__CRT_UUID_DECL(ILatLongReport, 0x7fed806d, 0x0ef8, 0x4f07, 0x80, 0xac, 0x36, 0xa0, 0xbe, 0xae, 0x31, 0x34)
__CRT_UUID_DECL(ILocationEvents, 0xcae02bbf, 0x798b, 0x4508, 0xa2, 0x07, 0x35, 0xa7, 0x90, 0x6d, 0xc7, 0x3d)
__CRT_UUID_DECL(ILocation, 0xab2ece69, 0x56d9, 0x4f28, 0xb5, 0x25, 0xde, 0x1b, 0x0e, 0xe4, 0x42, 0x37)
#endif
#endif
