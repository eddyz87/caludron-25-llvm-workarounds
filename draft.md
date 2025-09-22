# <TODO> A few words on BPF verifier

Main points:
- path tracing abstract interpretation:
  - propagates value ranges forward
  - caches visited states
- tracks values using range and known bits domains
- tracks linear relations between scalars in a limited way:
  - can track rA + B == rC + D
  - but only for 64-bit registers
  - and can drop the relation in many instances

Example:

```
Live regs before insn:
      0: .......... (85) call bpf_get_prandom_u32
      1: 0......... (bf) r1 = r0
      2: 01........ (07) r1 += 5
  .-- 3: 01........ (35) if r0 >= 0x5 goto pc+5
  |   4: .1........ (18) r0 = 0xffffc90000188000
  |   6: 01........ (0f) r0 += r1
  |   7: 0......... (71) r0 = *(u8 *)(r0 +0)
  |   8: 0......... (95) exit
  '-> 9: .......... (b7) r0 = 42
     10: 0......... (95) exit

0: (85) call bpf_get_prandom_u32    ; R0=scalar()
1: (bf) r1 = r0                     ; R0=scalar(id=1) R1=scalar(id=1)
2: (07) r1 += 5                     ; R1=scalar(id=1+5)
3: (35) if r0 >= 0x5 goto pc+5      ; R0=scalar(id=1,umin=0,umax=4)
4: (18) r0 = 0xffffc90000188000     ; R0=map_value()
6: (0f) r0 += r1                    ; R0=map_value(umin=5,umax32=9)
7: (71) r0 = *(u8 *)(r0 +0)         ; R0=scalar(umin=0,umax=255)
8: (95) exit

from 3 to 9: R0=scalar(id=1,umin=5) R1=scalar(id=1) R10=fp0
9: R0=scalar(id=1,umin=5) R1=scalar(id=1) R10=fp0
9: (b7) r0 = 42                     ; R0=42
10: (95) exit
```

# Workarounds in the LLVM code

## CO-RE relocations and `llvm.bpf.passthrough`
### Short CO-RE description

```c
struct bpf_iter__task_vma {
	struct vm_area_struct *vma;
} __attribute__((preserve_access_index));


struct bpf_iter__task_vma *ctx = ...;
...
ctx->vma;
```

`vma` field offset is not a compile time constant, instead, relocation
is recorded for memory load instruction. BPF program loader patches
offset corresponding to the `vma` field offset in currently running
program.

### Example

C:

	vma = ctx->vma;

IR:

        compile time global constant, name is used to
        encode details like type name, CO-RE relocation kind
        for machine code generation.
                        |
`%ctx` is an input      |                          uid counter
  |                     v                              |
  | %0 = load i64, ptr @"llvm.bpf_iter__task_vma:0:16$0:2:0", align 8
  '-----------------------------.                      |
                                v                      |
    %1 = getelementptr i8, ptr %ctx, i64 %0            v
    %2 = tail call ptr @llvm.bpf.passthrough.p0.p0(i32 2, ptr %1)
    %3 = load ptr, ptr %2, align 8

BPF:

    ;  struct vm_area_struct *vma = ctx->vma;
       2:       r8 = *(u64 *)(r1 + 0x10)
                0000000000000010:  CO-RE <byte_off> [2] struct bpf_iter__task_vma::<anon 2>.vma (0:2:0)

### `llvm.bpf.passthrough`

    ; Signature is T -> T
    %2 = tail call ptr @llvm.bpf.passthrough.p0.p0(i32 <uid>, ptr <pointer>)

A compile time construct making each CO-RE load/store/property-read
chain unique. Used to:
- avoid sharing same load/store instructions with other chains or
  non-CORE operations, allowing to folding:

     r8 = *(u64 *)(r1 + 0x10)
     0000000000000010:  CO-RE <byte_off> [2] struct bpf_iter__task_vma::<anon 2>.vma (0:2:0)

- prevent certain code motion optimizations
  (example one the next slide).

### `llvm.bpf.passthrough` and code motion

[Source](https://reviews.llvm.org/D87153)

#### slide #1

``` c
p1 = llvm.bpf.builtin.preserve.struct.access(base, 0, 0);
p2 = llvm.bpf.builtin.preserve.struct.access(p1, 1, 2);
a = llvm.bpf.builtin.preserve_field_info(p2, EXIST);
if (a) {
  p1 = llvm.bpf.builtin.preserve.struct.access(base, 0, 0);
  p2 = llvm.bpf.builtin.preserve.struct.access(p1, 1, 2);
  ... use p2 ...
}
```

#### slide #2

```c
p1 = llvm.bpf.builtin.preserve.struct.access(base, 0, 0);
p2 = llvm.bpf.builtin.preserve.struct.access(p1, 1, 2);
a = llvm.bpf.builtin.preserve_field_info(p2, EXIST);
if (a) {
  ... use p2 ...
}
```

#### slide #3

For a specific kernel, where field for `p2` does not exist,
this resolves to:

```c
p1 = base + 10
p2 = <poison>;
a = 0;
if (a) {
  ... dead code ...
}
```

Which cannot be verified or executed.
Effectively `llvm.bpf.builtin.preserve.struct.access` has verification
time side effects. Hence, it is incorrect to move such calls out from
conditional branches.

## `BPFAdjustOptImpl::avoidSpeculation`

### slide #1

From C point of view the two programs below are identical:

```c
off = ...
if (off < 42) {
  ptr = packet_data + off;
  ... *ptr ...
}
```

```c
off = ...
ptr = packet_data + off;
if (off < 42) {
  ... *ptr ...
}
```

### slide #2

This is a problem for verifier, because:

```c
off = ...
ptr = packet_data + off;
if (off < 42) {
  ... *ptr ...
}
```

Verifier does not track relations between scalars and pointers, so it
can't propagate range backwards from `off` to `ptr`

### slide #3

LLVM BPF backend attempts to block such code motion by inserting
passthrough calls:

```c
off = ...
if (off < 42) {
  off = __builtin_bpf_passthrough(<seq_num>, off);
  ptr = packet_data + off;
  ... *ptr ...
}
```

By matching value definition, `icmp` and memory access pattern.
(and trying to avoid too many such calls).

Note: highlight different parts of the pattern with different colors.

### reproducer (skip in presentation)

The reproducer actually fails with clang master:
- IR level transformation prevents `arr + v` moving before `if (v < 10)`, but
- Early Machine Loop Invariant Code Motion (early-machinelicm) does it anyway,
  after passthrough calls are already eliminated.

```c
unsigned char arr[10];
unsigned long x, s;

SEC("socket")
__success
int foo3(void)
{
        unsigned long v;

        v = x;
        for (unsigned long i = s; i < 100; i++)
                if (v < 10)
                        arr[v] += i;
        return 0;
}
```

```
func#0 @0
Live regs before insn:
      0: .......... (18) r1 = 0xffa0000000198018  ;; reading s
      2: .1........ (79) r3 = *(u64 *)(r1 +0)
      3: ...3...... (25) if r3 > 0x63 goto pc+10
      4: ...3...... (18) r1 = 0xffa0000000198010
      6: .1.3...... (79) r1 = *(u64 *)(r1 +0)     ;; v = x
      7: .1.3...... (18) r2 = 0xffa0000000198000  ;; r2 = arr
      9: .123...... (0f) r2 += r1                 ;; r2 = arr + v
     10: .123...... (05) goto pc+5
  1  11: .12.4..... (bf) r3 = r4
  1  12: .1234..... (07) r3 += 1
  1  13: .1234..... (a5) if r4 < 0x63 goto pc+2
     14: .......... (b4) w0 = 0
     15: 0......... (95) exit
  1  16: .123...... (bf) r4 = r3
  1  17: .12.4..... (25) if r1 > 0x9 goto pc-7
  1  18: .12.4..... (71) r3 = *(u8 *)(r2 +0)
  1  19: .1234..... (0c) w3 += w4
  1  20: .1234..... (73) *(u8 *)(r2 +0) = r3
  1  21: .12.4..... (05) goto pc-11
0: R1=ctx() R10=fp0
; for (unsigned long i = s; i < 100; i++) @ verifier_and.c:157
0: (18) r1 = 0xffa0000000198018       ; R1=map_value(map=verifier.bss,ks=4,vs=32,off=24)
2: (79) r3 = *(u64 *)(r1 +0)          ; R1=map_value(map=verifier.bss,ks=4,vs=32,off=24) R3=scalar()
3: (25) if r3 > 0x63 goto pc+10       ; R3=scalar(smin=smin32=0,smax=umax=smax32=umax32=99,var_off=(0x0; 0x7f))
; v = x; @ verifier_and.c:156
4: (18) r1 = 0xffa0000000198010       ; R1=map_value(map=verifier.bss,ks=4,vs=32,off=16)
6: (79) r1 = *(u64 *)(r1 +0)          ; R1=scalar()
7: (18) r2 = 0xffa0000000198000       ; R2=map_value(map=verifier.bss,ks=4,vs=32)
9: (0f) r2 += r1
math between map_value pointer and register with unbounded min value is not allowed
processed 7 insns (limit 1000000) max_states_per_insn 0 total_states 0 peak_states 0 mark_read 0
```

### note on matched pattern (skip in presentation)

The actual pattern matched by transformation looks as follows
(modified comment from the source code):

    B1:
      var = ... load or call ...
      ...
    Bx:
      comp1 = icmp <opcode> var, <const>; /* icmp must be in in a different block */
      if (comp1) goto B2 else B3;
    B2:
	  <abort transformation if CallInst | Load | Store are present here
	   as these would most likely block getelementptr hoisting>
      ... getelementptr(... var ...) or ...
      ... sext(... var ...) or ...
      ... zext(... var ...) or ...
	      ^^^^
		  assuming that these are used by getelementptr but not checking

But this is a bit too much details for the presentation.

## `BPFAdjustOptImpl::serializeICMP{Cross,}BB`
### slide #1

LLVM rewrites the following C program:

```c
if (v < 1)
        return 0;
if (v > 7)
        return 0;
return arr[v];
```

To an equivalent of the following:

```c
t = v;
t -= 8;
if ((unsigned)t < (unsigned)-7)
	return 0;
return arr[v];
```

### slide #2

This is a problem for verifier:

```
... v is input in w1, t is w2 ...
3: (bc) w2 = w1                       ; R1=R2=scalar(id=1,umin=0,umax=0xffffffff)
4: (04) w2 += -8                      ; R2=scalar(umin=0,umax=0xffffffff...)
5: (a6) if w2 < 0xfffffff9 goto pc+5  ; R2=scalar(...smin32=-7,smax32=-1...)
; v = bpf_get_prandom_u32();
6: (bc) w1 = w1                       ; R1=scalar(id=1,umin=0,umax=0xffffffff...)
; return arr[v];
7: (18) r2 = <arr> ll                 ; R2=map_value(...)
9: (0f) r2 += r1
10: (71) r0 = *(u8 *)(r2 +0)
R2 unbounded memory access, make sure to bounds check any such access
```

At (4) verifier drops relationship between `r1` and `r2`, as it does
not track linear relations after 32-bit operations.

* w[0-9] - 32-bit sub-registers
* r[0-9] - 64-bit registers

### slide #3

The workaround is two hide the fact that both conditionals work on a
same value from optimizer.

Match a sequence of basic blocks ending with `icmp`:

```llvm
entry:
  %cmp = icmp ult i64 %x, 1
  br i1 %cmp, label %if.then, label %if.end

if.end:
  %cmp1 = icmp ugt i64 %x, 7
  br i1 %cmp1, label %if.then2, label %if.end3
```

And obfuscate `%x` value for the first `icmp`:

```llvm
entry:
  %cmp = icmp ult i64 %x, 1
  %2 = call i1 @llvm.bpf.passthrough.i1.i1(i32 2, i1 %cmp)
  br i1 %2, label %if.then, label %if.end

if.end:
  %cmp1 = icmp ugt i64 %x, 7
  br i1 %cmp1, label %if.then2, label %if.end3

```
### slide #4 code after workaround

Conditionals remain as-is:

```asm
        r1 = x ll
        r1 = *(u64 *)(r1 + 0)
        if r1 == 0 goto ...
        if r1 > 7 goto ...
        r2 = arr ll
        r2 += r1
        w0 = *(u8 *)(r2 + 0)
```

### slide #5

`BPFAdjustOptImpl::serializeICMPInBB` applies same workaround to a
similar pattern:

```
        if (v < 1 || v > 7)
                return 0;
        return arr[v];
```

### reproducer (skip in presentation) #1

```c
unsigned char arr[10];

SEC("socket")
__success
unsigned foo2(void)
{
        long v;

        v = bpf_get_prandom_u32();
        if (v < 1)
                return 0;
        if (v > 7)
                return 0;
        return arr[v];
}
```

```
0: R1=ctx() R10=fp0
; v = bpf_get_prandom_u32(); @ verifier_and.c:140
0: (85) call bpf_get_prandom_u32#7    ; R0=scalar()
1: (bc) w1 = w0                       ; R0=scalar() R1=scalar(smin=0,smax=umax=0xffffffff,var_off=(0x0; 0xffffffff))
2: (b4) w0 = 0                        ; R0=0
; if (v < 1) @ verifier_and.c:141
3: (bc) w2 = w1                       ; R1=scalar(id=1,smin=0,smax=umax=0xffffffff,var_off=(0x0; 0xffffffff)) R2=scalar(id=1,smin=0,smax=umax=0xffffffff,var_off=(0x0; 0xffffffff))
4: (04) w2 += -8                      ; R2=scalar(smin=0,smax=umax=0xffffffff,var_off=(0x0; 0xffffffff))
5: (a6) if w2 < 0xfffffff9 goto pc+5          ; R2=scalar(smin=umin=umin32=0xfffffff9,smax=umax=0xffffffff,smin32=-7,smax32=-1,var_off=(0xfffffff8; 0x7))
; v = bpf_get_prandom_u32(); @ verifier_and.c:140
6: (bc) w1 = w1                       ; R1=scalar(id=1,smin=0,smax=umax=0xffffffff,var_off=(0x0; 0xffffffff))
; return arr[v]; @ verifier_and.c:145
7: (18) r2 = 0xffa0000000198000       ; R2=map_value(map=verifier.bss,ks=4,vs=24)
9: (0f) r2 += r1
10: R1=scalar(id=1,smin=0,smax=umax=0xffffffff,var_off=(0x0; 0xffffffff)) R2=map_value(map=verifier.bss,ks=4,vs=24,smin=0,smax=umax=0xffffffff,var_off=(0x0; 0xffffffff))
10: (71) r0 = *(u8 *)(r2 +0)
R2 unbounded memory access, make sure to bounds check any such access
processed 10 insns (limit 1000000) max_states_per_insn 0 total_states 0 peak_states 0 mark_read 0
```

### reproducer (skip in presentation) #2

```c
unsigned char arr[10];
unsigned long x;

SEC("socket")
__success
unsigned foo2(void)
{
        unsigned long v;

        v = x;
        if (v < 1 || v > 7)
                return 0;
        return arr[v];
}

```

```
0: R1=ctx() R10=fp0
; unsigned foo2(void) @ verifier_and.c:118
0: (b4) w0 = 0                        ; R0=0
; v = x; @ verifier_and.c:122
1: (18) r1 = 0xffffc90000188000       ; R1=map_value(map=verifier.bss,ks=4,vs=18)
3: (79) r1 = *(u64 *)(r1 +0)          ; R1=scalar()
; if (v < 1 || v > 7) @ verifier_and.c:123
4: (bf) r2 = r1                       ; R1=scalar(id=1) R2=scalar(id=1)
5: (07) r2 += -8                      ; R2=scalar()
6: (a5) if r2 < 0xfffffff9 goto pc+4          ; R2=scalar(smin=smin32=-7,smax=smax32=-1,umin=0xfffffffffffffff9,umin32=0xfffffff9,var_off=(0xfffffffffffffff8; 0x7))
; return arr[v]; @ verifier_and.c:125
7: (18) r2 = 0xffffc90000188008       ; R2=map_value(map=verifier.bss,ks=4,vs=18,off=8)
9: (0f) r2 += r1
math between map_value pointer and register with unbounded min value is not allowed
```

## (conv)a < power_2_const

f63405f6e3d3 BPF: Workaround an InstCombine ICmp transformation with llvm.bpf.compare builtin
Handled by `BPFAdjustOptImpl::adjustICmpToBuiltin()`.

### slide #1

LLVM can transform the following C code:

``` c
int foo(long x) {
  if ((unsigned)x <= 1)
    return arr[x];
  return 0;
}
```

To an equivalent of:

``` c
int foo(long x) {
  if (x & 0xfffffffe)
    return arr[x];
  return 0;
}
```

### slide #2

This is a problem for verifier:

```asm
 6: (18) r2 = 0xfffffffe              ; R2=0xfffffffe
; if ((unsigned)x <= 1) {
 8: (bf) r3 = r1                      ; R1=scalar(id=1) R3=scalar(id=1)
 9: (5f) r3 &= r2                     ; R3=scalar(...umin=0,umax=0xfffffffe...)
10: (55) if r3 != 0x0 goto pc+6       ; R3=0
; return arr[x];
11: (18) r2 = <arr> ll                ; R2=map_value(...)
13: (0f) r2 += r1
math between map_value pointer and register with unbounded min value is not allowed
```

- (9) `r3 &= r2` breaks the relation between `r3` and `r2`
- (10) no range for `r1` inferred from `r3 == 0` branch entry

### slide #3

The workaround is two hide comparison from optimizer.
Match icmp with a power of two operand:

```llvm
  %cmp = icmp ule i32 %conv, 1
  br i1 %cmp, label %if.then, label %if.end
```

And replace it with the a call to a backend specific intrinsic:

```llvm
  %0 = call i1 @llvm.bpf.compare.i32.i32(i32 37, i32 %conv, i32 1)
  br i1 %0, label %if.then, label %if.end
```

### reproducer (skip in presentation)

```c
unsigned long x;
char arr[10];

__weak
int foo(long x)
{
        if ((unsigned)x <= 1) {
                return arr[x];
        }
        return 0;
}

SEC("socket")
__success
int foo3(void)
{
        foo(x);
        return 0;
}
```

## Verifier limitation `BPFCheckAndAdjustIR::sinkMinMax`

18e13739b8c0 [BPF] Undo transformation for LICM.cpp:hoistMinMax()
https://lore.kernel.org/bpf/20230406164505.1046801-1-yhs@fb.com/

### slide #1

There is also a transformation to help with verifier omission in old
kernels. Older versions of verifier can predict jump for the following
program:

```asm
   10: (79) r1 = *(u64 *)(r10 -16)       ; R1_w=scalar() R10=fp0
   11: (b7) r2 = 0                       ; R2_w=0
   12: (2d) if r1 < r2 goto pc+2
```

But cannot predict the jump for inverted condition;

```asm
   12: (2d) if r2 > r1 goto pc+2
```

Predictions were carried only for `<non_const> <cond_op> <const>`
pattern.

### slide #2

There is an LLVM transformation that applies the following rewrites:

    x < a && x < b   ->   x < min(a, b)
    x > a || x > b   ->   x > min(a, b)
    x < a || x < b   ->   x < max(a, b)
    x > a && x > b   ->   x > max(a, b)

When `b` is a constant and `a` is not, translation for `min` pattern
worsens jump predictions:

```asm
    r1 = ... a ...
    r2 = ... b ...
    r3 = ... x ...
    if r1 < r2 goto +1;  ; can't be predicted
    r1 = r2;
    if r3 < r1 goto ...  ; can't be predicted
```

```c
    r1 = ... a ...
    r2 = ... b ...
    r3 = ... x ...
    if r3 >= r1 goto ... ; can't be predicted
    if r3 >= r2 goto ... ; can be predicted
```

### slide #3

There is an LLVM pass that reverts min/max patterns:

    x < min(a, b) -> x < a && x < b
    x > min(a, b) -> x > a || x > b
    x < max(a, b) -> x < a || x < b
    x > max(a, b) -> x > a && x > b

But only for loop bodies, where each unpredicted branch becomes very
costly for verifier.

## `BPFPreserveStaticOffsetPass`
### slide #1

Certain types are special for BPF verifier, consider the program:

```c
SEC("cgroup/getsockopt")
int foo(struct bpf_sockopt *ctx) {
        unsigned g = 0;
        switch (ctx->level) {             // level offset 24
        case 10:
                g = bar(ctx->sk->family); // sk offset 0
                break;
        case 20:
                g = bar(ctx->optlen);     // optlen offset 32
                break;
        }
        return g % 2;
}
```

- `ctx` is in `r1` at the start of program execution
- verifier tracks it as a "pointer to context" type
- `struct bpf_sockopt` is not a real structure, verifier remaps
  `ctx->{level,sk,optlen}` access to corresponding fields of
  `struct bpf_sockopt_kern`
- it does so by matching load and stores with static offsets,
  e.g. for `level` it looks for `*(u32 *)(r1 + 24)`.

### slide #2

Sinking the call to `bar` is a valid transformation:

```c
        switch (ctx->level) {
        case 10:
                p = (void *)ctx->sk + 4;
                break;
        case 20:
                p = ctx + 32;
                break;
        }
		g = bar(*p);
        return g % 2;
```

But it confuses verifier, because `ctx` is no longer access via static offset:

```asm
; switch (ctx->level) {
0: (61) r2 = *(u32 *)(r1 +24)         ; R1=ctx() R2=scalar(...)
1: (16) if w2 == 0x14 goto pc+5       ; R2=scalar(...)
2: (b4) w0 = 0                        ; R0=0
3: (56) if w2 != 0xa goto pc+7        ; R2=10
; g = bar(ctx->sk->family);
4: (79) r1 = *(u64 *)(r1 +0)          ; R1=sock()
5: (07) r1 += 4
R1 pointer arithmetic on sock prohibited
```

### slide #3

The workaround is to use a special attribute: `preserve_static_offset`.
Presence of this offset allows the following rewrite right after
frontend:

```c
struct bpf_sockopt { ... } __attribute__((preserve_static_offset));

        switch (@llvm.bpf.getelementptr.and.load.i32(ctx, 24)) {
        case 10:
                g = bar(ctx->sk->family); // offsets of 0 are not tinkered with
                break;
        case 20:
                g = bar(@llvm.bpf.getelementptr.and.load.i32(ctx, 32));
                break;
        }
```

### reproducer (skip in presentation)

```c
__weak __u32 magic2(__u32 x)
{
        return x;
}

SEC("cgroup/getsockopt")
int foo4(struct bpf_sockopt *ctx) {
        unsigned g = 0;
        switch (ctx->level) {
        case 10:
                g = magic2(ctx->sk->family);
                break;
        case 20:
                g = magic2(ctx->optlen);
                break;
        }
        return g % 2;
}
```

# User-visible workarounds

## barrier_var()

``` diff
--- a/tools/lib/bpf/bpf_helpers.h
+++ b/tools/lib/bpf/bpf_helpers.h
@@ -123,7 +123,7 @@
  * This is a variable-specific variant of more global barrier().
  */
 #ifndef barrier_var
-#define barrier_var(var) asm volatile("" : "+r"(var))
+#define barrier_var(var) ((void)(var))
 #endif
```

Failing tests (cpuv4):

#144/46  iters/iter_search_loop:FAIL
Issue: ???

#430/1   task_local_data/task_local_data_basic:FAIL
#430/2   task_local_data/task_local_data_race:FAIL
Issue: ???

#444     tcp_custom_syncookie:FAIL
#647/1   xdp_synproxy/xdp:FAIL
#647/2   xdp_synproxy/tc:FAIL
Issue: ??? but see log below

#526/28  verifier_iterating_callbacks/test2:FAIL
#526/29  verifier_iterating_callbacks/test3:FAIL
#526/30  verifier_iterating_callbacks/test4:FAIL
Issue: array pointer is incremented directly,
       w/o arithmetic usomg induction variable.

#613     verif_scale_strobemeta_bpf_loop:FAIL
Issue: ???

#64      cgroup_storage:FAIL
Issue: ???


### bounds check hoisting

Main problem:

Live regs before insn:
      0: .......... (85) call bpf_get_prandom_u32#7
      1: 0......... (bf) r1 = r10
      2: 01........ (0f) r1 += r0
      3: 01........ (c5) if r0 s< 0xfffffe00 goto pc+2
      4: 01........ (65) if r0 s> 0xffffffff goto pc+1
      5: .1........ (71) r0 = *(u8 *)(r1 +0)
      6: 0......... (95) exit
Global function bounds_check_after_ptr_arith() doesn't return scalar. Only those are supported.
0: R1=ctx() R10=fp0
; asm volatile ("					\ @ verifier_and.c:117
0: (85) call bpf_get_prandom_u32#7    ; R0_w=scalar()
1: (bf) r1 = r10                      ; R1_w=fp0 R10=fp0
2: (0f) r1 += r0
mark_precise: frame0: last_idx 2 first_idx 0 subseq_idx -1
mark_precise: frame0: regs=r0 stack= before 1: (bf) r1 = r10
mark_precise: frame0: regs=r0 stack= before 0: (85) call bpf_get_prandom_u32#7
math between fp pointer and register with unbounded min value is not allowed
processed 3 insns (limit 1000000) max_states_per_insn 0 total_states 0 peak_states 0 mark_read 0

Instances of this problem:

    static __always_inline u8 *next(struct tcpopt_context *ctx, __u32 sz)
                 .------------ packet pointer
                 v
	data = ctx->data + off;
	barrier_var(data);
	if (data + sz >= ctx->data_end)
		return NULL;
	ctx->off += sz;
	return data;

	opsize = next(ctx, 1);
	if (!opsize || *opsize < 2)
		return 1;


1028: (bf) r8 = r5                    ; frame1: R5=R8=pkt(id=59,r=0,smin=umin=smin32=umin32=1,smax=umax=smax32=umax32=0xffff,var_off=(0x0; 0xffff)) cb
1029: (07) r8 += 1                    ; frame1: R8=pkt(id=59,off=1,r=0,smin=umin=smin32=umin32=1,smax=umax=smax32=umax32=0xffff,var_off=(0x0; 0xffff)) cb
1030: (3d) if r8 >= r6 goto pc-23     ; frame1: R6=pkt_end() R8=pkt(id=59,off=1,r=0,smin=umin=smin32=umin32=1,smax=umax=smax32=umax32=0xffff,var_off=(0x0; 0xffff)) cb
; ctx->off += sz; @ xdp_synproxy_kern.c:213
  ...
; if (!opsize || *opsize < 2) @ xdp_synproxy_kern.c:232
1034: (71) r9 = *(u8 *)(r5 +0)


					if (likely(off < __PAGE_SIZE - size)) {		\
						barrier_var(off);			\
						if (off > 0)				\
							data = _data + off;		\
					}						\
	struct_p = tld_get_data(&tld_obj, value2, "value2", sizeof(struct test_tld_struct));
	if (struct_p)
		test_value2 = *struct_p;


150: (bc) w1 = w0                     ; R0=R1=scalar(id=37,smin=0,smax=umax=0xffffffff,var_off=(0x0; 0xffffffff))
151: (04) w1 += -4064                 ; R1=scalar(smin=0,smax=umax=0xffffffff,var_off=(0x0; 0xffffffff))
152: (a6) if w1 < 0xfffff021 goto pc+16       ; R1=scalar(smin=umin=umin32=0xfffff021,smax=umax=0xffffffff,smin32=-4063,smax32=-1,var_off=(0xfffff000; 0xfff))
153: (bc) w3 = w0                     ; R0=R3=scalar(id=37,smin=0,smax=umax=0xffffffff,var_off=(0x0; 0xffffffff))
154: (05) goto pc-35
120: (0f) r9 += r3                    ; R3=scalar(id=37,smin=0,smax=umax=0xffffffff,var_off=(0x0; 0xffffffff))
                                        R9=mem(sz=4096,smin=0,smax=umax=0xffffffff,var_off=(0x0; 0xffffffff))
; test_value2 = *struct_p; @ test_task_local_data.c:54
121: (79) r1 = *(u64 *)(r9 +24)
R9 unbounded memory access, make sure to bounds check any such access


444     tcp_custom_syncookie -> same as xdp_synproxy_kern.c


    #define ARR_LONG_SZ 1000
	for (i = zero; i < ARR_LONG_SZ && can_loop; i++) {
		barrier_var(i);
		arr_long[i] = i;
	}

; for (i = zero; i < ARR_LONG_SZ && can_loop; i++) { @ verifier_iterating_callbacks.c:629
0: (18) r1 = 0xffffc900074b7004       ; R1=map_value(map=verifier.bss,ks=4,vs=1000008,off=4)
2: (61) r2 = *(u32 *)(r1 +0)          ; R1=map_value(map=verifier.bss,ks=4,vs=1000008,off=4) R2=scalar(smin=0,smax=umax=0xffffffff,var_off=(0x0; 0xffffffff))
3: (26) if w2 > 0x3e7 goto pc+12      ; R2=scalar(smin=smin32=0,smax=umax=smax32=umax32=999,var_off=(0x0; 0x3ff))
4: (bf) r3 = r2                       ; R2=scalar(id=1,smin=smin32=0,smax=umax=smax32=umax32=999,var_off=(0x0; 0x3ff)) R3=scalar(id=1,smin=smin32=0,smax=umax=smax32=umax32=999,var_off=(0x0; 0x3ff))
5: (67) r3 <<= 3                      ; R3=scalar(smin=smin32=0,smax=umax=smax32=umax32=7992,var_off=(0x0; 0x1ff8))
6: (18) r1 = 0xffffc900075b4000       ; R1=map_value(map=.data.arr_long,ks=4,vs=8000)
8: (0f) r1 += r3                      ; R1=map_value(map=.data.arr_long,ks=4,vs=8000,smin=smin32=0,smax=umax=smax32=umax32=7992,var_off=(0x0; 0x1ff8)) R3=scalar(smin=smin32=0,smax=umax=smax32=umax32=7992,var_off=(0x0; 0x1ff8))
9: (bf) r3 = r2                       ; R2=scalar(id=1,smin=smin32=0,smax=umax=smax32=umax32=999,var_off=(0x0; 0x3ff)) R3=scalar(id=1,smin=smin32=0,smax=umax=smax32=umax32=999,var_off=(0x0; 0x3ff))
10: (e5) may_goto pc+5
11: R1=map_value(map=.data.arr_long,ks=4,vs=8000,smin=smin32=0,smax=umax=smax32=umax32=7992,var_off=(0x0; 0x1ff8)) R2=scalar(id=1,smin=smin32=0,smax=umax=smax32=umax32=999,var_off=(0x0; 0x3ff)) R3=scalar(id=1,smin=smin32=0,smax=umax=smax32
=umax32=999,var_off=(0x0; 0x3ff)) R10=fp0
; arr_long[i] = i; @ verifier_iterating_callbacks.c:631
11: (7b) *(u64 *)(r1 +0) = r3         ; R1=map_value(map=.data.arr_long,ks=4,vs=8000,smin=smin32=0,smax=umax=smax32=umax32=7992,var_off=(0x0; 0x1ff8)) R3=scalar(id=1,smin=smin32=0,smax=umax=smax32=umax32=999,var_off=(0x0; 0x3ff))
; for (i = zero; i < ARR_LONG_SZ && can_loop; i++) { @ verifier_iterating_callbacks.c:629
12: (07) r1 += 8                      ; R1=map_value(map=.data.arr_long,ks=4,vs=8000,off=8,smin=smin32=0,smax=umax=smax32=umax32=7992,var_off=(0x0; 0x1ff8))
13: (bf) r2 = r3                      ; R2=scalar(id=1,smin=smin32=0,smax=umax=smax32=umax32=999,var_off=(0x0; 0x3ff)) R3=scalar(id=1,smin=smin32=0,smax=umax=smax32=umax32=999,var_off=(0x0; 0x3ff))
14: (07) r2 += 1                      ; R2=scalar(id=1+1,smin=umin=smin32=umin32=1,smax=umax=smax32=umax32=1000,var_off=(0x0; 0x3ff))
15: (a5) if r3 < 0x3e7 goto pc-7 9: R1=map_value(map=.data.arr_long,ks=4,vs=8000,off=8,smin=smin32=0,smax=umax=smax32=umax32=7992,var_off=(0x0; 0x1ff8)) R2=scalar(id=1,smin=umin=smin32=umin32=1,smax=umax=smax32=umax32=999,var_off=(0x0; 0x7
ff)) R3=scalar(id=1,smin=smin32=0,smax=umax=smax32=umax32=998,var_off=(0x0; 0x3ff)) R10=fp0
; for (i = zero; i < ARR_LONG_SZ && can_loop; i++) { @ verifier_iterating_callbacks.c:629
9: (bf) r3 = r2                       ; R2=scalar(id=1,smin=umin=smin32=umin32=1,smax=umax=smax32=umax32=999,var_off=(0x0; 0x7ff)) R3=scalar(id=1,smin=umin=smin32=umin32=1,smax=umax=smax32=umax32=999,var_off=(0x0; 0x7ff))
10: (e5) may_goto pc+5                ; R1=map_value(map=.data.arr_long,ks=4,vs=8000,off=8,smin=smin32=0,smax=umax=smax32=umax32=7992,var_off=(0x0; 0x1ff8)) R2=scalar() R3=scalar() R10=fp0
; arr_long[i] = i; @ verifier_iterating_callbacks.c:631
11: (7b) *(u64 *)(r1 +0) = r3
invalid access to map value, value_size=8000 off=8000 size=8
R1 max value is outside of the allowed memory range
processed 22 insns (limit 1000000) max_states_per_insn 1 total_states 3 peak_states 3 mark_read 0
 =============
#526/28  verifier_iterating_callbacks/test2:FAIL

Fails:

0000000000000848 <test2>:
; test2():
; /home/eddy/work/bpf-next/tools/testing/selftests/bpf/progs/verifier_iterating_callbacks.c:629
;       for (i = zero; i < ARR_LONG_SZ && can_loop; i++) {
     265:       r1 = 0x0 ll
                0000000000000848:  R_BPF_64_64  zero
     267:       w2 = *(u32 *)(r1 + 0x0)
     268:       if w2 > 0x3e7 goto +0xc <LBB41_4>
     269:       r3 = r2
     270:       r3 <<= 0x3
     271:       r1 = 0x0 ll
                0000000000000878:  R_BPF_64_64  arr_long
     273:       r1 += r3
<L0>:
     274:       r3 = r2
; /home/eddy/work/bpf-next/tools/testing/selftests/bpf/progs/verifier_iterating_callbacks.c:629
;       for (i = zero; i < ARR_LONG_SZ && can_loop; i++) {
     275:       may_goto +0x5 <LBB41_4>
; /home/eddy/work/bpf-next/tools/testing/selftests/bpf/progs/verifier_iterating_callbacks.c:631
;               arr_long[i] = i;
     276:       *(u64 *)(r1 + 0x0) = r3
; /home/eddy/work/bpf-next/tools/testing/selftests/bpf/progs/verifier_iterating_callbacks.c:629
;       for (i = zero; i < ARR_LONG_SZ && can_loop; i++) {
     277:       r1 += 0x8
     278:       r2 = r3
     279:       r2 += 0x1
     280:       if r3 < 0x3e7 goto -0x7 <L0>

00000000000008c8 <LBB41_4>:
; LBB41_4():
; /home/eddy/work/bpf-next/tools/testing/selftests/bpf/progs/verifier_iterating_callbacks.c:633
;       return 0;
     281:       w0 = 0x0
     282:       exit

Passes:

0000000000000848 <test2>:
; test2():
; /home/eddy/work/bpf-next/tools/testing/selftests/bpf/progs/verifier_iterating_callbacks.c:629
;       for (i = zero; i < ARR_LONG_SZ && can_loop; i++) {
     265:       r1 = 0x0 ll
                0000000000000848:  R_BPF_64_64  zero
     267:       w1 = *(u32 *)(r1 + 0x0)
     268:       if w1 > 0x3e7 goto +0x9 <LBB41_3>
<L0>:
     269:       may_goto +0x8 <LBB41_3>
; /home/eddy/work/bpf-next/tools/testing/selftests/bpf/progs/verifier_iterating_callbacks.c:632
;               arr_long[i] = i;
     270:       r2 = r1
     271:       r2 <<= 0x3
     272:       r3 = 0x0 ll
                0000000000000880:  R_BPF_64_64  arr_long
     274:       r3 += r2
     275:       *(u64 *)(r3 + 0x0) = r1
; /home/eddy/work/bpf-next/tools/testing/selftests/bpf/progs/verifier_iterating_callbacks.c:629
;       for (i = zero; i < ARR_LONG_SZ && can_loop; i++) {
     276:       r1 += 0x1
     277:       if r1 < 0x3e8 goto -0x9 <L0>

00000000000008b0 <LBB41_3>:
; LBB41_3():
; /home/eddy/work/bpf-next/tools/testing/selftests/bpf/progs/verifier_iterating_callbacks.c:634
;       return 0;
     278:       w0 = 0x0
     279:       exit

Problematic part:

<L0>:
     274:       r3 = r2
;       for (i = zero; i < ARR_LONG_SZ && can_loop; i++) {
     275:       may_goto +0x5 <LBB41_4>
;               arr_long[i] = i;
     276:       *(u64 *)(r1 + 0x0) = r3
;       for (i = zero; i < ARR_LONG_SZ && can_loop; i++) {
     277:       r1 += 0x8
     278:       r2 = r3
     279:       r2 += 0x1
     280:       if r3 < 0x3e7 goto -0x7 <L0>

No upper bound for r1.
