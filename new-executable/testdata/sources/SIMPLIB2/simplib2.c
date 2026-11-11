#include <windows.h>        
                        
void FAR PASCAL simplib_method(char char_value, int int_value, char *ptr)
{                    
    char buf[2];
    buf[0]=char_value;
    buf[1]='\0';
    OutputDebugString(buf);
}                  