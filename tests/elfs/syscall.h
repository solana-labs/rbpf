/**
 * @brief Syscall function used in the BPF to BPF call test
 */

#pragma once

uint64_t syscall_function(uint64_t x);
uint64_t entrypoint_syscall_function(uint64_t x);
