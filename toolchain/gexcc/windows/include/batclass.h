/* batclass.h (gexcc-win's compatibility headers): the battery class's user-mode
 * part, the IOCTLs and structures a program queries a battery with; the
 * miniport interface is kernel-mode */
#pragma once
#include <windows.h>
#include <winioctl.h>

DEFINE_GUID(GUID_DEVICE_BATTERY, 0x72631e54, 0x78a4, 0x11d0, 0xbc, 0xf7, 0x00, 0xaa, 0x00, 0xb7, 0xb3, 0x2a);

#define IOCTL_BATTERY_QUERY_TAG         CTL_CODE(FILE_DEVICE_BATTERY, 0x10, METHOD_BUFFERED, FILE_READ_ACCESS)
#define IOCTL_BATTERY_QUERY_INFORMATION CTL_CODE(FILE_DEVICE_BATTERY, 0x11, METHOD_BUFFERED, FILE_READ_ACCESS)
#define IOCTL_BATTERY_SET_INFORMATION   CTL_CODE(FILE_DEVICE_BATTERY, 0x12, METHOD_BUFFERED, FILE_WRITE_ACCESS)
#define IOCTL_BATTERY_QUERY_STATUS      CTL_CODE(FILE_DEVICE_BATTERY, 0x13, METHOD_BUFFERED, FILE_READ_ACCESS)

#define BATTERY_TAG_INVALID 0

#define BATTERY_CAPACITY_RELATIVE 0x40000000
#define BATTERY_IS_SHORT_TERM     0x20000000
#define BATTERY_SET_CHARGE_SUPPORTED    0x00000001
#define BATTERY_SET_DISCHARGE_SUPPORTED 0x00000002
#define BATTERY_SYSTEM_BATTERY    0x80000000

#define BATTERY_POWER_ON_LINE 0x00000001
#define BATTERY_DISCHARGING   0x00000002
#define BATTERY_CHARGING      0x00000004
#define BATTERY_CRITICAL      0x00000008

#define BATTERY_UNKNOWN_CAPACITY 0xffffffff
#define BATTERY_UNKNOWN_VOLTAGE  0xffffffff
#define BATTERY_UNKNOWN_RATE     0x80000000

typedef enum _BATTERY_QUERY_INFORMATION_LEVEL {
    BatteryInformation,
    BatteryGranularityInformation,
    BatteryTemperature,
    BatteryEstimatedTime,
    BatteryDeviceName,
    BatteryManufactureDate,
    BatteryManufactureName,
    BatteryUniqueID,
    BatterySerialNumber
} BATTERY_QUERY_INFORMATION_LEVEL;

typedef struct _BATTERY_QUERY_INFORMATION {
    ULONG BatteryTag;
    BATTERY_QUERY_INFORMATION_LEVEL InformationLevel;
    LONG AtRate;
} BATTERY_QUERY_INFORMATION, *PBATTERY_QUERY_INFORMATION;

typedef struct _BATTERY_INFORMATION {
    ULONG Capabilities;
    UCHAR Technology;
    UCHAR Reserved[3];
    UCHAR Chemistry[4];
    ULONG DesignedCapacity;
    ULONG FullChargedCapacity;
    ULONG DefaultAlert1;
    ULONG DefaultAlert2;
    ULONG CriticalBias;
    ULONG CycleCount;
} BATTERY_INFORMATION, *PBATTERY_INFORMATION;

typedef struct _BATTERY_WAIT_STATUS {
    ULONG BatteryTag;
    ULONG Timeout;
    ULONG PowerState;
    ULONG LowCapacity;
    ULONG HighCapacity;
} BATTERY_WAIT_STATUS, *PBATTERY_WAIT_STATUS;

typedef struct _BATTERY_STATUS {
    ULONG PowerState;
    ULONG Capacity;
    ULONG Voltage;
    LONG Rate;
} BATTERY_STATUS, *PBATTERY_STATUS;
