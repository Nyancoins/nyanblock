#include "tools.h"

int array_compare_u8(const char* a, const char* b, size_t len) {
    for(int i = 0; i < len; ++i) {
        if(a[i] < b[i]) return -1;
        if(a[i] > b[i]) return 1;
    }

    return 0;
}

int32_t swap_endian(int32_t v) {
    int32_t swapped = ((v>>24)&0xff) | // move byte 3 to byte 0
                    ((v<<8)&0xff0000) | // move byte 1 to byte 2
                    ((v>>8)&0xff00) | // move byte 2 to byte 1
                    ((v<<24)&0xff000000); // byte 0 to byte 3
    return swapped;
}

const int SECOND = 1;
const int MINUTE = 60 * SECOND;
const int HOUR = 60 * MINUTE;
const int DAY = 24 * HOUR;
const int MONTH = 30 * DAY;
const int YEAR = 12 * MONTH;

int timeago(char *dest, size_t dest_maxlen, time_t unixtime) {
    time_t now = time(NULL);
    time_t diff = abs(unixtime - now);
    int pos = 0;
    char *comma = "";

    
    if(diff > YEAR) {
        uint32_t years = diff / YEAR;
        diff -= years * YEAR;
        pos += snprintf(dest + pos, dest_maxlen, "%u years", years);
        comma = ", ";
    }

    if(diff > MONTH) {
        uint32_t months = diff / MONTH;
        diff -= months * MONTH;
        pos += snprintf(dest + pos, dest_maxlen, "%s%u months", comma, months);
        comma = ", ";
    }

    if(diff > DAY) {
        uint32_t days = diff / DAY;
        diff -= days * DAY;
        pos += snprintf(dest + pos, dest_maxlen, "%s%u days", comma, days);
        comma = ", ";
    }

    if(diff > HOUR) {
        uint32_t hours = diff / HOUR;
        diff -= hours * HOUR;
        pos += snprintf(dest + pos, dest_maxlen, "%s%u hours", comma, hours);
        comma = ", ";
    }

    if(diff > MINUTE) {
        uint32_t minutes = diff / MINUTE;
        diff -= minutes * MINUTE;
        pos += snprintf(dest + pos, dest_maxlen, "%s%u minutes", comma, minutes);
        comma = ", ";
    }

    if(diff > SECOND) {
        uint32_t seconds = diff / SECOND;
        diff -= seconds * SECOND;
        pos += snprintf(dest + pos, dest_maxlen, "%s%u seconds", comma, seconds);
        comma = ", ";
    }

    if(diff == SECOND) {
        uint32_t seconds = diff / SECOND;
        diff -= seconds * SECOND;
        pos += snprintf(dest + pos, dest_maxlen, "%s%u second", comma, seconds);
        comma = ", ";
    }

    pos += snprintf(dest + pos, dest_maxlen, " ago");
    return pos;

    /*

    if(diff < 1*MINUTE) {
        if(diff <= 1) {
            snprintf(dest, dest_maxlen, "a second ago");
        } else {
            snprintf(dest, dest_maxlen, "%d seconds ago", diff);
        }
    }

    if(diff < 2*MINUTE) {
        snprintf(dest, dest_maxlen, "a minute ago");
    }

    if(diff < 45*MINUTE) {
        snprintf(dest, dest_maxlen, "%d minutes ago", diff/MINUTE);
    }

    if(diff < 90*MINUTE) {
        snprintf(dest, dest_maxlen, "an hour ago");
    }

    if(diff < 24*HOUR) {
        snprintf(dest, dest_maxlen, "%d hours ago", diff/HOUR);
    }

    if(diff < 48*HOUR) {
        snprintf(dest, dest_maxlen, "yesterday");
    }

    if(diff < 30*DAY) {
        snprintf(dest, dest_maxlen, "%d days ago", diff/DAY);
    }

    if(diff < 12*MONTH) {
        snprintf(dest, dest_maxlen, "%d months ago", diff/MONTH);
    }

    if(diff < 1*YEAR) {
        snprintf(dest, dest_maxlen, "a year ago");
    } else {
        snprintf(dest, dest_maxlen, "%d years ago", diff/YEAR);
    }
    */
    
}

double GetDifficulty(const uint32_t bits) {
    int shift = (bits >> 24) & 0xff;
    double diff = (double)0x0000ffff / (double)(bits & 0x00ffffff);

    while (shift < 29)
    {
        diff *= 256.0;
        shift++;
    }
    while (shift > 29)
    {
        diff /= 256.0;
        shift--;
    }

    return diff;
}
