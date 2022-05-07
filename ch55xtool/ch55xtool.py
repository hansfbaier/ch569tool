#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import sys
import math
import argparse

import usb.core
import usb.util


# ======= Some C-like static constants =======
DFU_ID_VENDOR = 0x4348
DFU_ID_PRODUCT = 0x55e0

EP_OUT_ADDR = 0x02
EP_IN_ADDR = 0x82

USB_MAX_TIMEOUT = 2000

DETECT_CHIP_CMD_V2 = [
    0xa1, 0x12, 0x00,
    0x52, 0x11, 0x4d,
    0x43, 0x55, 0x20,
    0x49, 0x53, 0x50,
    0x20, 0x26, 0x20,
    0x57, 0x43, 0x48,
    0x2e, 0x43, 0x4e]
END_FLASH_CMD_V2 = [0xa2, 0x01, 0x00, 0x00]
RESET_RUN_CMD_V2 = [0xa2, 0x01, 0x00, 0x01]
SEND_KEY_CMD_V20 = [0xa3, 0x30, 0x00]
SEND_KEY_CMD_V23 = [0xa3, 0x38, 0x00] + [0x00] * 0x38
SEND_KEY_CMD_V27_ZERO = [0xa3, 0x2f, 0x00] + [0x00] * 0x2f
SEND_KEY_CMD_V27        = [0xa3, 0x2f, 0x00, 0x3d, 0xd5, 0x85, 0x81, 0x17, 0xa9, 0x26, 0x86, 0x91, 0xdc, 0xe8, 0x6f, 0x85, 0x32, 0x8c, 0xcd, 0xce, 0x6c, 0xe4, 0xf6, 0xfd, 0x24, 0x2e, 0x05, 0x4d, 0xf8, 0xa0, 0x22, 0xda, 0xea, 0x44, 0x04, 0x0d, 0x07, 0x06, 0xb3, 0x5b, 0x47, 0x0c, 0x93, 0x2f, 0xb5, 0x45, 0x9e, 0x24, 0xcf, 0x45]
SEND_KEY_CMD_V27_VERIFY = [0xa3, 0x2f, 0x00, 0x18, 0xb0, 0x60, 0x5c, 0xf2, 0x84, 0x01, 0x61, 0x6c, 0xb7, 0xc3, 0x4a, 0x60, 0x0d, 0x67, 0xa8, 0xa9, 0x47, 0xbf, 0xd1, 0xd8, 0xff, 0x09, 0xe0, 0x28, 0xd3, 0x7b, 0xfd, 0xb5, 0xc5, 0x1f, 0xdf, 0xe8, 0xe2, 0xe1, 0x8e, 0x36, 0x22, 0xe7, 0x6e, 0x0a, 0x90, 0x20, 0x79, 0xff, 0xaa, 0x20]
ERASE_CHIP_CMD_V2 = [0xa4, 0x01, 0x00, 0x08]
ERASE_CHIP_CMD_V27 = [0xa4, 0x04, 0x00, 0x00, 0x00, 0x00, 0x00]
WRITE_CMD_V2 = [0xa5, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]
VERIFY_CMD_V2 = [0xa6, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]
READ_CFG_CMD_V2 = [0xa7, 0x02, 0x00, 0x1f, 0x00]
DUMP_ROM_CMD = [0xab, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]

ENABLE_DEBUG_CMD = [
  0xa8, 0x0e, 0x00, 0x07,
  0x00, 0x11, 0xbf, 0xf9,
  0xf7, 0x13, 0xbf, 0xf9,
  0xec, 0xe5, 0xf2, 0xff, 0x8f
]

CH55X_IC_REF = {}
CH55X_IC_REF[0x51] = {
    'device_name': 'CH551',
    'device_flash_size': 10240,
    'device_dataflash_size': 128,
    'chip_id': 0x51}
CH55X_IC_REF[0x52] = {
    'device_name': 'CH552',
    'device_flash_size': 16384,
    'device_dataflash_size': 128,
    'chip_id': 0x52}
CH55X_IC_REF[0x53] = {
    'device_name': 'CH553',
    'device_flash_size': 10240,
    'device_dataflash_size': 128,
    'chip_id': 0x53}
CH55X_IC_REF[0x54] = {
    'device_name': 'CH554',
    'device_flash_size': 14336,
    'device_dataflash_size': 128,
    'chip_id': 0x54}
CH55X_IC_REF[0x59] = {
    'device_name': 'CH559',
    'device_flash_size': 61440,
    'device_dataflash_size': 128,
    'chip_id': 0x59}
CH55X_IC_REF[0x69] = {
    'device_name': 'CH569',
    'device_flash_size': 448 * 1024,
    'device_dataflash_size': 32 * 1024,
    'chip_id': 0x69}

DEBUG = True
# =============================================

def __to_hex(str):
    return " ".join(f"{c:02x}" for c in str)

def __get_dfu_device(idVendor=DFU_ID_VENDOR, idProduct=DFU_ID_PRODUCT):
    dev = usb.core.find(idVendor=idVendor, idProduct=idProduct)
    if dev is None:
        return (None, 'NO_DEV_FOUND')
    try:
        if dev.is_kernel_driver_active(0):
            try:
                dev.detach_kernel_driver(0)
            except usb.core.USBError:
                return (None, 'USB_ERROR_CANNOT_DETACH_KERNEL_DRIVER')
    except BaseException:
        pass  # Windows dont need detach

    try:
        dev.set_configuration()
    except usb.core.USBError:
        return (None, 'USB_ERROR_CANNOT_SET_CONFIG')

    try:
        usb.util.claim_interface(dev, 0)
    except usb.core.USBError:
        return (None, 'USB_ERROR_CANNOT_CLAIM_INTERFACE')

    return (dev, '')


def __detect_ch55x_v2(dev):
    dev.write(EP_OUT_ADDR, b'\xa1\x12\x00B\x10MCU ISP & WCH.CN')
    ret = dev.read(EP_IN_ADDR, 6, USB_MAX_TIMEOUT)
    if DEBUG: print(f" {__to_hex(ret)}")
    try:
        return CH55X_IC_REF[ret[4]]
    except KeyError:
        return None

def __dump_rom(dev, addr, length):
    cmd = DUMP_ROM_CMD.copy()
    cmd[3] = addr & 0xff
    cmd[4] = (addr >> 8) & 0xff
    cmd[7] = length & 0xff
    if DEBUG: print(f"dump ROM:\n{__to_hex(cmd)}")
    dev.write(EP_OUT_ADDR, cmd)
    ret = dev.read(EP_IN_ADDR, (6 + length) & 0xff, USB_MAX_TIMEOUT)
    if DEBUG: print(f" {__to_hex(ret)}")
    return ret[6:]

def __read_cfg_ch55x_v2(dev):
    if DEBUG: print(f"read config:\n{__to_hex(READ_CFG_CMD_V2)}")
    dev.write(EP_OUT_ADDR, READ_CFG_CMD_V2)
    ret = dev.read(EP_IN_ADDR, 30, USB_MAX_TIMEOUT)
    if DEBUG: print(f" {__to_hex(ret)}")

    ver_str = 'V%d.%d%d' % (ret[19], ret[20], ret[21])
    chk_sum = (ret[22] + ret[23] + ret[24] + ret[25]) & 0xff

    return (ver_str, chk_sum)


def __write_key_ch55x_v20(dev, chk_sum):
    SEND_KEY_CMD_V20 = SEND_KEY_CMD_V20 + [chk_sum] * 0x30

    dev.write(EP_OUT_ADDR, SEND_KEY_CMD_V20)
    ret = dev.read(EP_IN_ADDR, 6, USB_MAX_TIMEOUT)
    if DEBUG: print(f" {__to_hex(ret)}")

    if ret[3] == 0:
        return True
    else:
        return None


def __write_key_ch55x_v23(dev):
    if DEBUG: print(f"write key:\n{__to_hex(SEND_KEY_CMD_V23)}")
    dev.write(EP_OUT_ADDR, SEND_KEY_CMD_V23)
    ret = dev.read(EP_IN_ADDR, 6, USB_MAX_TIMEOUT)
    if DEBUG: print(f"{__to_hex(ret)}")

    if ret[3] == 0:
        return True
    else:
        return None

def __write_key_ch56x_v27(dev, key=SEND_KEY_CMD_V27):
    if DEBUG: print(f"\n{__to_hex(key)}")
    dev.write(EP_OUT_ADDR, key)
    ret = dev.read(EP_IN_ADDR, 6, USB_MAX_TIMEOUT)
    if DEBUG: print(f"{__to_hex(ret)}")

    if ret[3] == 0:
        return True
    else:
        return None

def __erase_chip_ch55x_v2(dev, binary_size):
    # Ceil the binary size to the next multiple of 0x1000
    erase_size = math.ceil(binary_size/0x1000) & 0xff
    print('Erase size: 0x%x' % (erase_size * 0x1000))
    cmd = ERASE_CHIP_CMD_V2.copy()
    cmd[3] = erase_size
    if DEBUG: print(f"write erase chip: \n{__to_hex(cmd)}")
    dev.write(EP_OUT_ADDR, cmd)
    ret = dev.read(EP_IN_ADDR, 6, USB_MAX_TIMEOUT)
    if DEBUG: print(f"{__to_hex(ret)}")

    if ret[3] == 0:
        return True
    else:
        return None

def __erase_chip_ch56x_v27(dev, binary_size):
    # Ceil the binary size to the next multiple of 0x1000
    erase_size = math.ceil(binary_size/0x1000) * 4
    print('Erase size: 0x%x' % (erase_size * 0x1000))
    cmd = ERASE_CHIP_CMD_V27.copy()
    cmd[3] = erase_size & 0xff
    cmd[4] = (erase_size >> 8) & 0xff
    cmd[5] = (erase_size >> 16) & 0xff
    cmd[6] = (erase_size >> 24) & 0xff
    if DEBUG: print(f"write erase chip: {__to_hex(cmd)}")
    dev.write(EP_OUT_ADDR, cmd)
    ret = dev.read(EP_IN_ADDR, 6, USB_MAX_TIMEOUT)
    if DEBUG: print(f"{__to_hex(ret)}")

    if ret[3] == 0:
        return True
    else:
        return None

def __write_flash_ch55x_v20(dev, chk_sum, chip_id, payload):
    # Payload needs to be padded, 56 is a good number
    payload = payload + [0] * \
        ((math.ceil(len(payload) / 56) * 56) - len(payload))
    file_length = len(payload)

    for index in range(file_length):
        if index % 8 == 7:
            payload[index] = (
                payload[index] ^ (
                    (chk_sum + chip_id) % 256)) % 256
        else:
            payload[index] = (payload[index] ^ chk_sum) % 256

    left_len = file_length
    curr_addr = 0

    while curr_addr < file_length:

        if left_len >= 56:
            pkt_length = 56
        else:
            pkt_length = left_len

        __WRITE_CMD_V2 = WRITE_CMD_V2
        __WRITE_CMD_V2[1] = pkt_length + 5
        __WRITE_CMD_V2[3] = curr_addr % 256
        __WRITE_CMD_V2[4] = (curr_addr >> 8) % 256
        __WRITE_CMD_V2[7] = left_len % 256
        __WRITE_CMD_V2 = __WRITE_CMD_V2 + \
            payload[curr_addr:curr_addr + pkt_length]

        if DEBUG: print(f"write flash: {__to_hex(__WRITE_CMD_V2)}")
        dev.write(EP_OUT_ADDR, __WRITE_CMD_V2)
        ret = dev.read(EP_IN_ADDR, 6, USB_MAX_TIMEOUT)
        if DEBUG: print(f" {__to_hex(ret)}\n")

        curr_addr = curr_addr + pkt_length
        left_len = left_len - pkt_length

        if ret[4] != 0x00:
            return None

    return file_length

def __write_flash_ch56x_v27(dev, chk_sum, chip_id, payload):
    # Payload needs to be padded, 56 is a good number
    #print(f"orig payload length: {len(payload)}")
    #payload = payload + [0] * \
    #    ((math.ceil(len(payload) / 56) * 56) - len(payload))
    file_length = len(payload)
    if DEBUG: print(f"file_length: {file_length}")

    payload = payload.copy()

    payload = payload + [0] * \
    ((math.ceil(len(payload) / 56) * 56) - len(payload))
    file_length = len(payload)

    #xor_key = [0xb6, 0x27, 0xdd, 0xa0, 0x1f, 0xd9, 0xbf, 0x1f]
    xor_key = [chk_sum] * 7 + [(chk_sum + chip_id) & 0xff]
    for index in range(file_length):
        payload[index] ^= xor_key[index % len(xor_key)]

    left_len = file_length
    curr_addr = 0
    pkt_length = 56

    while curr_addr < file_length:
        if left_len >= 56:
            pkt_length = 56
        else:
            pkt_length = left_len

        #if DEBUG: print(f"curr_addr: {curr_addr:x}, left_len: {left_len:x} of {file_length:x}")
        __WRITE_CMD_V2 = WRITE_CMD_V2
        __WRITE_CMD_V2[1] = pkt_length + 5
        __WRITE_CMD_V2[3] = curr_addr         & 0xff
        __WRITE_CMD_V2[4] = (curr_addr >> 8)  & 0xff
        __WRITE_CMD_V2[5] = (curr_addr >> 16) & 0xff
        __WRITE_CMD_V2[6] = (curr_addr >> 24) & 0xff
        __WRITE_CMD_V2[7] = left_len          & 0xff
        __WRITE_CMD_V2 = __WRITE_CMD_V2 + \
            payload[curr_addr:curr_addr + pkt_length]

        if DEBUG: print(f"{__to_hex(__WRITE_CMD_V2)}")
        dev.write(EP_OUT_ADDR, __WRITE_CMD_V2)
        ret = dev.read(EP_IN_ADDR, 6, USB_MAX_TIMEOUT)
        if DEBUG: print(f"{__to_hex(ret)}\n")

        curr_addr += pkt_length
        left_len -= pkt_length

        if ret[4] != 0x00:
            return None

    return file_length

def __verify_flash_ch55x_v20(dev, chk_sum, chip_id, payload):
    # Payload needs to be padded, 56 is a good number
    payload = payload + [0] * \
        ((math.ceil(len(payload) / 56) * 56) - len(payload))
    file_length = len(payload)

    for index in range(file_length):
        if index % 8 == 7:
            payload[index] = (
                payload[index] ^ (
                    (chk_sum + chip_id) & 0xff)) & 0xff

    left_len = file_length
    curr_addr = 0

    while curr_addr < file_length:

        if left_len >= 56:
            pkt_length = 56
        else:
            pkt_length = left_len

        __VERIFY_CMD_V2 = VERIFY_CMD_V2
        __VERIFY_CMD_V2[1] = pkt_length + 5
        __VERIFY_CMD_V2[3] = curr_addr & 0xff
        __VERIFY_CMD_V2[4] = (curr_addr >> 8)  & 0xff
        __VERIFY_CMD_V2[5] = (curr_addr >> 16) & 0xff
        __VERIFY_CMD_V2[6] = (curr_addr >> 24) & 0xff
        __VERIFY_CMD_V2[7] = left_len          & 0xff
        __VERIFY_CMD_V2 = __VERIFY_CMD_V2 + \
            payload[curr_addr:curr_addr + pkt_length]

        dev.write(EP_OUT_ADDR, __VERIFY_CMD_V2)
        ret = dev.read(EP_IN_ADDR, 6, USB_MAX_TIMEOUT)

        curr_addr = curr_addr + pkt_length
        left_len = left_len - pkt_length

        if ret[4] != 0x00:
            return None

    return file_length


def __verify_flash_ch55x_v23(dev, chk_sum, chip_id, payload):
    # Payload needs to be padded, 56 is a good number
    payload = payload + [0] * \
        ((math.ceil(len(payload) / 56) * 56) - len(payload))
    file_length = len(payload)

    for index in range(file_length):
        if index % 8 == 7:
            payload[index] = (
                payload[index] ^ (
                    (chk_sum + chip_id) % 256)) % 256
        else:
            payload[index] = (payload[index] ^ chk_sum) % 256

    left_len = file_length
    curr_addr = 0

    while curr_addr < file_length:

        if left_len >= 56:
            pkt_length = 56
        else:
            pkt_length = left_len

        __VERIFY_CMD_V2 = VERIFY_CMD_V2
        __VERIFY_CMD_V2[1] = pkt_length + 5
        __VERIFY_CMD_V2[3] = curr_addr % 256
        __VERIFY_CMD_V2[4] = (curr_addr >> 8) % 256
        __VERIFY_CMD_V2[7] = left_len % 256
        __VERIFY_CMD_V2 = __VERIFY_CMD_V2 + \
            payload[curr_addr:curr_addr + pkt_length]

        if DEBUG: print(f"{__to_hex(__VERIFY_CMD_V2)}")
        dev.write(EP_OUT_ADDR, __VERIFY_CMD_V2)
        ret = dev.read(EP_IN_ADDR, 6, USB_MAX_TIMEOUT)
        if DEBUG: print(f" {__to_hex(ret)}\n")

        if ret[4] != 0x00:
            print(f"verify failed at address: 0x{curr_addr:x} of 0x{file_length:x}")
            return None

        curr_addr = curr_addr + pkt_length
        left_len = left_len - pkt_length

    return file_length

def __verify_flash_ch56x_v27(dev, chk_sum, chip_id, payload):
    # Payload needs to be padded, 56 is a good number
    #payload = payload + [0] * \
    #    ((math.ceil(len(payload) / 56) * 56) - len(payload))
    file_length = len(payload)
    payload = payload.copy()

    payload = payload + [0] * \
        ((math.ceil(len(payload) / 56) * 56) - len(payload))
    file_length = len(payload)

    #xor_key = [0xd3, 0x4c, 0xfa, 0xcd, 0x44, 0x06, 0xe4, 0x3c]
    xor_key = [chk_sum] * 7 + [(chk_sum + chip_id) & 0xff]
    for index in range(file_length):
        payload[index] ^= xor_key[index % len(xor_key)]

    left_len = file_length
    curr_addr = 0

    while curr_addr < file_length:

        if left_len >= 56:
            pkt_length = 56
        else:
            pkt_length = left_len

        __VERIFY_CMD_V2 = VERIFY_CMD_V2
        __VERIFY_CMD_V2[1] = pkt_length + 5
        __VERIFY_CMD_V2[3] = curr_addr & 0xff
        __VERIFY_CMD_V2[4] = (curr_addr >> 8)  & 0xff
        __VERIFY_CMD_V2[5] = (curr_addr >> 16) & 0xff
        __VERIFY_CMD_V2[6] = (curr_addr >> 24) & 0xff
        __VERIFY_CMD_V2[7] = 0x1e #left_len          & 0xff
        __VERIFY_CMD_V2 = __VERIFY_CMD_V2 + \
            payload[curr_addr:curr_addr + pkt_length]


        if DEBUG: print(f"{__to_hex(__VERIFY_CMD_V2)}")
        dev.write(EP_OUT_ADDR, __VERIFY_CMD_V2)
        ret = dev.read(EP_IN_ADDR, 6, USB_MAX_TIMEOUT)
        if DEBUG: print(f"{__to_hex(ret)}\n")

        if ret[4] != 0x00:
            print(f"verify failed at address: 0x{curr_addr:x} of 0x{file_length:x}")
            #return None

        curr_addr = curr_addr + pkt_length
        left_len = left_len - pkt_length

    return file_length

def __enable_debug_ch55x_v2(dev):
    if DEBUG: print(f"enable debug: {__to_hex(ENABLE_DEBUG_CMD)}")
    dev.write(EP_OUT_ADDR, ENABLE_DEBUG_CMD)
    ret = dev.read(EP_IN_ADDR, 6, USB_MAX_TIMEOUT)
    if DEBUG: print(f" {__to_hex(ret)}\n")

    if ret[4] != 0x00:
        return None
    else:
        return True

def __end_flash_ch55x_v2(dev):
    dev.write(EP_OUT_ADDR, END_FLASH_CMD_V2)
    ret = dev.read(EP_IN_ADDR, 6, USB_MAX_TIMEOUT)
    if ret[4] != 0x00:
        return None
    else:
        return True


def __restart_run_ch55x_v2(dev):
    dev.write(EP_OUT_ADDR, RESET_RUN_CMD_V2)


def main():
    parser = argparse.ArgumentParser(
        description="USBISP Tool For WinChipHead CH55x.")
    parser.add_argument(
        '-f',
        '--file',
        type=str,
        default='',
        help="The target file to be flashed. This must be a binary file (hex files are not supported).")
    parser.add_argument(
        '-v',
        '--verify',
        action='store_true',
        default=False,
        help="verify file only, do not write"
    )
    parser.add_argument(
        '-r',
        '--reset_after_flash',
        action='store_true',
        default=False,
        help="Reset after finsh flash.")
    parser.add_argument(
        '-d',
        '--enable_debug_interface',
        action='store_true',
        default=False,
        help="Enable the SWD debug interface on the device"
    )
    parser.add_argument(
        '--dump',
        action='store_true',
        default=False,
        help="dump ROM contents"
    )
    args = parser.parse_args()

    ret = __get_dfu_device()
    if ret[0] is None:
        print('Failed to get device, please check your libusb installation.')
        sys.exit(-1)

    dev = ret[0]

    ret = __detect_ch55x_v2(dev)
    if ret is None:
        print('Unable to detect CH55x.')
        print('Welcome to report this issue with a screen shot from the official CH55x tool.')
        sys.exit(-1)

    print('Found %s.' % ret['device_name'])
    chip_id = ret['chip_id']

    if args.file != '':
        payload = list(open(args.file, 'rb').read())
        if len(payload) > ret['device_flash_size']:
            print('The binary is too large for the device.')
            print('Binary size: 0x%x, Flash size: 0x%x' % (len(payload), ret['device_flash_size']))
            sys.exit(-1)

    ret = __read_cfg_ch55x_v2(dev)
    chk_sum = ret[1]
    if DEBUG: print(f"checksum: 0x{chk_sum:x}")

    print('BTVER: %s.' % ret[0])

    if args.file != '':
        payload = list(open(args.file, 'rb').read())
        if args.file.endswith('.hex') or args.file.endswith('.ihx') or payload[0]==58:
            print("WARNING: This looks like a hex file. This tool only supports binary files.")

        if ret[0] in ['V2.70']:
            ret = __write_key_ch56x_v27(dev, SEND_KEY_CMD_V27_ZERO)
            if ret is None:
                sys.exit('Failed to write key to CH56x.')

            if not args.verify:
                ret = __erase_chip_ch56x_v27(dev, len(payload))
                if ret is None:
                    sys.exit('Failed to erase CH55x.')

                ret = __write_flash_ch56x_v27(dev, chk_sum, chip_id, payload)
                if ret is None:
                    sys.exit('Failed to flash firmware of CH56x.')

            chk_sum = __read_cfg_ch55x_v2(dev)[1]

            ret = __write_key_ch56x_v27(dev, SEND_KEY_CMD_V27_ZERO)
            if ret is None:
                sys.exit('Failed to write key to CH56x.')

            ret = __verify_flash_ch56x_v27(dev, chk_sum, chip_id, payload)
            if ret is None:
                sys.exit('Failed to verify firmware of CH55x.')
        else:
            sys.exit('Bootloader version not supported.')

        if DEBUG:
            for i in range(0x8000 // 0x20):
                __dump_rom(dev, i * 0x20, 0x20)

        if args.reset_after_flash:
            __restart_run_ch55x_v2(dev)
            print('Restart and run.')
        else:
            ret = __end_flash_ch55x_v2(dev)
            if ret is None:
                sys.exit('Failed to end flash process.')
            print('Flash done.')

    if args.dump:
        ret = __enable_debug_ch55x_v2(dev)
        if ret is None:
            sys.exit("Failed to enable debug mode")
        for i in range(0x8000 // 0x20):
            print(__to_hex(__dump_rom(dev, i * 0x20, 0x20)))

    if args.enable_debug_interface:
        if ret[0] in ['V2.70']:
            ret = __enable_debug_ch55x_v2(dev)
            if ret is None:
                sys.exit("Failed to enable debug mode")
            ret = __read_cfg_ch55x_v2(dev)
            if DEBUG: print(f"checksum: 0x{ret[1]:x}")
            __end_flash_ch55x_v2(dev)
            print('done.')
        else:
            sys.exit('Bootloader version not supported.')
