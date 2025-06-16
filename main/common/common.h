typedef enum {
    DEBUG,
    INFO,
    WARN,
    ERROR
} logLevel;

extern logLevel log_level;

void LOG(logLevel level, const char* format, ...);