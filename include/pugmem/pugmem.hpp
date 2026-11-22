#pragma once

#include "pugmem/pattern.hpp"
#include "pugmem/process.hpp"
#include "pugmem/syscall.hpp"

namespace pug {

inline process& memory = *new process();

}