#include "common.h"

#include <stdio.h>
#include <stdarg.h>
#include <time.h>
#include <unistd.h>

#include <vector>
#include <cstdint>

// using byte_vec = std::vector<uint8_t>;

// void sendSocket(int sock, const byte_vec& data) {
// }


logLevel log_level = DEBUG;

// ANSI color codes for log levels
static const char* level_colors[] = {
    "\033[36m", // DEBUG - Cyan
    "\033[32m", // INFO - Green
    "\033[33m", // WARN - Yellow
    "\033[31m"  // ERROR - Red
};
static const char* level_names[] = {
    "DEBUG",
    "INFO",
    "WARN",
    "ERROR"
};
#define COLOR_RESET "\033[0m"

void LOG(logLevel level,const char* format, ...){
    if (level < log_level) return;
    va_list args;
    va_start(args, format);
    time_t now = time(0);
    struct tm tstruct;
    char buf[80];
    tstruct = *localtime(&now);
    strftime(buf, sizeof(buf), "%Y-%m-%d %X", &tstruct);
    printf("%s[%s] [%s]%s ", level_colors[level], buf, level_names[level], COLOR_RESET);
    vprintf(format, args);
    va_end(args);
}



