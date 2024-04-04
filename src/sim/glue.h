#ifndef GLUE_H
#define GLUE_H

#include <seccomp.h>
#include <linux/seccomp.h>

typedef unsigned int u_int;
typedef unsigned char u_char;
typedef unsigned short u_short;

#define __bounded(args)

unsigned int arc4random ();

#define bpf_maxbufsize (sizeof (struct seccomp_data))

#endif
