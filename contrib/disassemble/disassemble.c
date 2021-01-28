#define __USE_GNU 1
#define _GNU_SOURCE 1

#include <linux/types.h>
#include <linux/filter.h>
#include <linux/seccomp.h>
#include <linux/unistd.h>
#include <signal.h>
#include <stdio.h>
#include <stddef.h>
#include <string.h>
#include <sys/prctl.h>
#include <unistd.h>

#define STREQ(a,b) (strcmp (a,b) == 0)

int
disassemble (int fd, int raw)
{
  struct sock_filter f;
  ssize_t ret;

  while (1)
    {
      ret = read (fd, &f, sizeof (f));
      if (ret != sizeof (f))
        return 0;

      if (raw)
        printf ("{code:0x%x,\tjt:0x%x,\tjf:0x%x,\tk:0x%x}\n", f.code, f.jt, f.jf, f.k);
      else
        {
          const char *class = NULL;
          const char *mode = NULL;
          const char *src = NULL;
          const char *size = NULL;
          const char *op_alu = NULL;
          const char *op_jmp = NULL;

          switch (BPF_SIZE (f.code))
            {
            case BPF_W:
              size = "BPF_W";
              break;

            case BPF_H:
              size = "BPF_H";
              break;

            case BPF_B:
              size = "BPF_B";
              break;

            default:
              size = "<unknown>";
              break;
            }

          switch (BPF_MODE (f.code))
            {
            case BPF_IMM:
              mode = "BPF_IMM";
              break;

            case BPF_ABS:
              mode = "BPF_ABS";
              break;

            case BPF_IND:
              mode = "BPF_IND";
              break;

            case BPF_MEM:
              mode = "BPF_MEM";
              break;

            case BPF_LEN:
              mode = "BPF_LEN";
              break;

            case BPF_MSH:
              mode = "BPF_MSH";
              break;

            default:
              mode = "<unknown>";
              break;
            }

          switch (BPF_SRC (f.code))
            {
            case BPF_K:
              src = "BPF_K";
              break;

            case BPF_X:
              src = "BPF_X";
              break;

            default:
              src = "<unknown>";
              break;
            }

          switch (BPF_OP (f.code))
            {
            case BPF_ADD:
              op_alu = "BPF_ADD";
              break;

            case BPF_SUB:
              op_alu = "BPF_SUB";
              break;

            case BPF_MUL:
              op_alu = "BPF_MUL";
              break;

            case BPF_DIV:
              op_alu = "BPF_DIV";
              break;

            case BPF_OR:
              op_alu = "BPF_OR";
              break;

            case BPF_AND:
              op_alu = "BPF_AND";
              break;

            case BPF_LSH:
              op_alu = "BPF_LSH";
              break;

            case BPF_RSH:
              op_alu = "BPF_RSH";
              break;

            case BPF_NEG:
              op_alu = "BPF_NEG";
              break;

            case BPF_MOD:
              op_alu = "BPF_MOD";
              break;

            case BPF_XOR:
              op_alu = "BPF_XOR";
              break;

            default:
              op_alu = "<unknown>";
              break;
            }

          switch (BPF_OP (f.code))
            {
            case BPF_JA:
              op_jmp = "BPF_JA";
              break;

            case BPF_JEQ:
              op_jmp = "BPF_JEQ";
              break;

            case BPF_JGT:
              op_jmp = "BPF_JGT";
              break;

            case BPF_JGE:
              op_jmp = "BPF_JGE";
              break;

            case BPF_JSET:
              op_jmp = "BPF_JSET";
              break;

            default:
              op_jmp = "<unknown>";
              break;
            }


          switch (BPF_CLASS (f.code))
            {
            case BPF_LD:
              class = "BPF_LD";
              printf ("%s|%s|%s, k=0x%x\n", class, mode, size, f.k);
              break;

            case BPF_LDX:
              class = "BPF_LDX";
              printf ("%s|%s|%s, k=0x%x\n", class, mode, size, f.k);
              break;

            case BPF_ST:
              class = "BPF_ST";
              printf ("%s|%s|%s, k=0x%x\n", class, mode, size, f.k);
              break;

            case BPF_STX:
              class = "BPF_STX";
              printf ("%s|%s|%s, k=0x%x\n", class, mode, size, f.k);
              break;

            case BPF_ALU:
              class = "BPF_ALU";
              printf ("%s|%s|%s, k=0x%x\n", class, op_alu, src, f.k);
              break;

            case BPF_JMP:
              class = "BPF_JMP";
              printf ("%s|%s|%s, jt:%d, jf:%d, k=0x%x\n", class, op_jmp, src, f.jt, f.jf, f.k);
              break;

            case BPF_RET:
              class = "BPF_RET";
              if (BPF_SRC (f.code) != BPF_K)
                printf ("%s\n", class, f.k);
              else
                {

                  printf ("%s, k=0x%x\n", class, f.k);
                }
              break;

            case BPF_MISC:
              class = "BPF_MISC";
              printf ("%s (opcode=0x%x) (k=0x%x)\n", class, f.code, f.k);
              break;

            default:
              class = "<unknown>";
              break;
            }
        }
    }
}

int
main (int argc, char **argv)
{
  int i, raw = 0;

  for (i = 1; i < argc; i++)
    if (argc > 1 && STREQ (argv[1], "-r"))
      {
        raw = 1;
        break;
      }

  return disassemble (0, raw);
}
