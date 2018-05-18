/* Testing kernel structures access */

#include <linux/kernel.h>
#include <linux/module.h>

#include <linux/version.h>
#include <generated/autoconf.h>

#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,0)
#ifdef CONFIG_SMP
#define __SMP__
#endif

#if defined(CONFIG_MODVERSIONS) && !defined(MODVERSIONS)
#include <linux/modversions.h>
#define MODVERSIONS
#endif
#endif

#define LBLOG(...) printk (KERN_ALERT "LBI: " __VA_ARGS__)

bool true_ = true;
bool false_ = false;

int testfunc(int a) {
  return a*2;
}

struct AA {
  int a0;
  char *b0;
};

struct ASID {
  long int li;
  int i2;
  unsigned char bf1:1;
  unsigned char bf2:3;
  signed int bf3:12;
  unsigned int bf4:12;
  struct S1 {
    int a;
    char *b;
    struct {
      int aa;
      char *bb;
    } ff;
    struct AA zf[0];
  } f1;

  bool booli1;
  bool booli2;
  bool boolbf1:1;
  bool boolbf2:1;
  // Boolean array
  bool boolarr[6];

  struct AA *sptr;
  struct AA sarr[3];

  struct AA *sarrptr;
  struct AA *ptrarr[3];

  struct AA *nullptr;

  long *lptr;

  int *iptr;
  int **ipptr;
  int ***ippptr;

  int iarr2[5][3];

  int (*funcptr)(int);

  struct {
    int a1;
    char *b1;
    struct S1 *ptrarr[2];
    void *ptr;
    char buf[10];
    long ulb[3];
    union {
      int a;
      struct {
	int a;
	unsigned long long ull[10];
      } l3;
    } l2;
  } f2;

  struct AA f3;
  struct AA ze[];
};

struct ASID asid;
struct AA aa;
long seven = 7;
int six = 6;


struct node {
  int one;
  char *two;
};

typedef struct ASID asid_t;

asid_t aaa;

enum ASID_ENUM {ASID_0, ASID_2=2, ASID_3};

struct estruct {
  enum ASID_ENUM e1;
  int i2;
};

struct estruct eStruct;
enum ASID_ENUM asid_enum;

// Testing anonymous multilevel
struct ASID_ANON {
  struct {
    int a;			/* 0 */
    union {
      int b;			/* 4 */
      struct {
	int c;			/* 4 */
	int d;			/* 8 */
      };
    };
    struct {
      int e;			/* 12 */
    };
  };
};

struct ASID_ANON asid_anon;


// for tPtr testing
static int one = 1, two = 2, three = 3;
int *iPtr = &one;
int *iPtrarr[] = {&one, &two, &three};

static char *charPtrArr[3];

struct ASID_ptr {
  struct Internal {
    int a;
    struct AA *a3[3];
    struct AA *a0[0];
  } ii;
  struct AA *aa[4];
} asid_ptr;

static int __init
testmod_init(void) {

  int i, j;

  one = 1;
  LBLOG("++++++++++++++ testmod loaded\n");


  asid.li = 123456789;
  asid.i2 = -555;
  asid.bf1 = 1;
  asid.bf2 = 2;
  asid.bf3 = -2;
  asid.bf4 = 123;

  asid.booli1 = true;
  asid.booli2 = false;
  asid.boolbf1 = false;
  asid.boolbf2 = true;

  for (i=0; i < 6; i++)
    asid.boolarr[i] = (i%3) ? true : false;

  asid.f1.ff.bb = "bbstring";
  asid.f2.l2.l3.a = 666;
  asid.f2.buf[0] = 'b';
  asid.f2.buf[1] = 'u';
  asid.f2.buf[2] = 'f';
  asid.f2.buf[3] = '\0';
  asid.f2.ulb[0] = 1;
  asid.f2.ulb[1] = 2;
  asid.f2.ulb[2] = -3;

  aa.a0 = 740;
  asid.sptr = &aa;
  asid.lptr = &seven;
  asid.iptr = &six;
  asid.ipptr = &(asid.iptr);
  asid.ippptr = &(asid.ipptr);

  asid.sarr[0].a0 = 11;
  asid.sarr[1].a0 = 22;
  asid.sarr[2].a0 = 33;

  asid.sarrptr = &(asid.sarr[0]);
  asid.nullptr = NULL;

  asid.ptrarr[0] = &(asid.sarr[0]);
  asid.ptrarr[1] = &(asid.sarr[1]);
  asid.ptrarr[2] = &(asid.sarr[2]);

  for (i=0; i < 5; i++)
    for (j=0; j < 3; j++)
      asid.iarr2[i][j] = i*10+j;

  asid.funcptr = testfunc;

  {
    int i;
    static struct AA _aa[3] = {
      {0, "zero"},
      {1, "one"},
      {2, "two"}
    };

    for(i=0; i < 3; i++) {
      asid_ptr.ii.a3[i] =asid_ptr.aa[i] = &_aa[i];
      charPtrArr[i] = _aa[i].b0;
    }
  }



  return 0;
}


static void __exit
testmod_cleanup_module(void) {
  LBLOG("------------ testmod unloaded\n");
}

module_init(testmod_init);
module_exit(testmod_cleanup_module);

MODULE_LICENSE("GPL");
