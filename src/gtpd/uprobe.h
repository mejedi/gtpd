#pragma once

// UPROBE(name, ...)
//
// Define a "uprobe" - a tracepoint for dynamic external tracing
// with Linux uprobes.  Technically, it defines a function, to be invoked
// as usual.  Unless instrumented, the function does nothing.
//
// An external tool (e.g. bpftrace) could instrument the function to
// record an event whenever the function is invoked.  Tools are
// typically capable of capturing function arguments, hence arguments
// are useful to communicate additional information.
#define UPROBE(name, ...) \
_Pragma("GCC visibility push(default)") \
extern "C" { \
__attribute__((noinline, noclone)) void \
name(__VA_ARGS__) { asm volatile (""); } \
} \
_Pragma("GCC visibility pop")

// The implementation is somewhat involved as it has to prevent the
// optimiser from removing the function call.
