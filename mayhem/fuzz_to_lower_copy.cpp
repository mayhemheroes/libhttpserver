#include <stdint.h>
#include <stdio.h>

#define _HTTPSERVER_HPP_INSIDE_ 1

#include <fuzzer/FuzzedDataProvider.h>
#include "httpserver/string_utilities.hpp"


extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    FuzzedDataProvider provider(data, size);
    std::string str = provider.ConsumeRandomLengthString();
    httpserver::string_utilities::to_lower_copy(str);

    return 0;
}
