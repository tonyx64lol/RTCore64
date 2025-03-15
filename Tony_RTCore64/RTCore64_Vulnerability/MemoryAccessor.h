#pragma once
#include <cstdint>
#include <Windows.h>

class MemoryAccessor
{
public:
    struct MemoryOperation
    {
        uint8_t gap1[8];     // 8 bytes gap
        uint64_t address;  // 8 bytes
        uint8_t gap2[4];     // 4 bytes gap
        uint32_t offset;     // 4 bytes
        uint32_t size;       // 4 bytes
        uint32_t data;       // 4 bytes
        uint8_t gap3[16];    // 16 bytes gap
    };// Total size: 48 bytes

    HANDLE hDevice;

    ~MemoryAccessor();
    bool Open();
    bool ReadUint8(uintptr_t address, uint8_t* buffer);
    bool ReadUint16(uintptr_t address, uint16_t* buffer);
    bool ReadUint32(uintptr_t address, uint32_t* buffer);
    bool ReadMemory(uintptr_t address, void* buffer, size_t size);
    bool WriteUint8(uintptr_t address, uint8_t value);
    bool WriteUint16(uintptr_t address, uint16_t value);
    bool WriteUint32(uintptr_t address, uint32_t value);
    bool WriteMemory(uintptr_t address, const void* buffer, size_t size);
};

