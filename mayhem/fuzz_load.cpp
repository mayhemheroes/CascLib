#include <cstdlib>
#include <iostream>


#include "CascLib.h"
#include "CascCommon.h"

#include "FuzzedDataProvider.h"

template <CASC_FILE_INFO_CLASS INFO_T>
void get_file_info(HANDLE file_handle) {
    PCASC_FILE_SPAN_INFO span_info;
    std::size_t cb_length = 0;

    CascGetFileInfo(file_handle, CASC_FILE_INFO_CLASS::CascFileSpanInfo, &span_info, cb_length, &cb_length);
    if (cb_length != 0) {
        span_info = reinterpret_cast<PCASC_FILE_SPAN_INFO>(new BYTE[cb_length]);
        CascGetFileInfo(file_handle, INFO_T, span_info, cb_length, nullptr);
        CASC_FREE(span_info);
        span_info = nullptr;
    }
}

HANDLE get_file(FuzzedDataProvider& fdp, const FuzzFile& fuzz_file) {
    HANDLE storage_handle = nullptr;
    HANDLE file_handle = nullptr;
    auto fuzz_pv_file_name = fdp.ConsumeRandomLengthString();
    if (CascOpenStorage(fuzz_file.name.c_str(), 0, &storage_handle)) {
        CascOpenFile(storage_handle, fuzz_pv_file_name.c_str(), 0, 0, &file_handle);
    }
    return file_handle;
}

void fuzz_file_info(FuzzedDataProvider& fdp, HANDLE file_handle) {
    unsigned int chosen_test = fdp.ConsumeIntegral<unsigned int>() % 5;
    switch(chosen_test) {
        case 0:
            get_file_info<CascFileContentKey>(file_handle);
            break;
        case 1:
            get_file_info<CascFileEncodedKey>(file_handle);
            break;
        case 2:
            get_file_info<CascFileFullInfo>(file_handle);
            break;
        case 3:
            get_file_info<CascFileInfoClassMax>(file_handle);
            break;
        default:
            get_file_info<CascFileSpanInfo>(file_handle);
            break;
    }
}

void fuzz_file_read(HANDLE file_handle) {
    DWORD bytes_read;
    uint8_t buffer[1024];
    CascReadFile(file_handle, buffer, 1024, &bytes_read);
}

extern "C" __attribute__((unused)) int LLVMFuzzerTestOneInput(const uint8_t *fuzz_data, size_t size) {
    if (size < 1) {
        return -1;
    }

    FuzzedDataProvider fdp(fuzz_data, size);
    auto fuzz_file = fdp.ConsumeFile();
    auto file_handle = get_file(fdp, fuzz_file);
    if (file_handle == nullptr) {
        return -1;
    }

    if (fdp.ConsumeBool()) {
        fuzz_file_info(fdp, file_handle);
    } else {
        fuzz_file_read(file_handle);
    }
    return 0;
}