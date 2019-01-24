#ifndef __HELP_H__
#define __HELP_H__

#define WRITE_TO_SCREEN

#ifdef WRITE_TO_SCREEN
  #define write_log(...)	{ if(is_logs()) printf(__VA_ARGS__); }
#else
/*
 *@todo: need implementation
*/
  #define write_log(...)	fprintf(log_f, __VA_ARGS__)
#endif

void print_help(void);
void logs_output(int en);
int is_logs(void);

#endif //__HELP_H__