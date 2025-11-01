/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * Copyright (C) 2024 bmax121. All Rights Reserved.
 * Copyright (C) 2024 lzghzr. All Rights Reserved.
 * Fixed version for Android 13 compatibility
 */

#include <accctl.h>
#include <compiler.h>
#include <hook.h>
#include <kpmodule.h>
#include <kputils.h>
#include <taskext.h>
#include <linux/cred.h>
#include <linux/err.h>
#include <linux/fs.h>
#include <linux/kernel.h>
#include <linux/printk.h>
#include <linux/spinlock.h>
#include <linux/string.h>
#include <uapi/linux/limits.h>

#include "hosts_redirect.h"
#include "hr_utils.h"

KPM_NAME("hosts_redirect");
KPM_VERSION(MYKPM_VERSION);
KPM_LICENSE("GPL v2");
KPM_AUTHOR("lzghzr");
KPM_DESCRIPTION("redirect /system/etc/hosts to /data/adb/hosts/{name}");

struct open_flags;
struct file* (*do_filp_open)(int dfd, struct filename* pathname, const struct open_flags* op);

char hosts_source[] = "/system/etc/hosts";
char hosts_target[64] = "/data/adb/hosts/hosts";

static bool set_hosts(const char* name) {
  if (!name || strlen(name) > 40)
    return false;
  for (int i = 0;i <= strlen(name);i++) {
    hosts_target[16 + i] = name[i];
  }
#ifdef CONFIG_DEBUG
  logkm("hosts_target=%s\n", hosts_target);
#endif /* DEBUG */
  return true;
}

static void do_filp_open_before(hook_fargs3_t* args, void* udata) {
  args->local.data0 = 0;
  if (current_uid() != 0)
    return;
  if (unlikely(!strcmp(hosts_target, "/data/adb/hosts/disable")))
    return;

  struct filename* pathname = (struct filename*)args->arg1;

  // 简化的直接路径匹配 - 基于旧版稳定逻辑
  if (unlikely(!strcmp(pathname->name, hosts_source))) {
    args->local.data0 = (uint64_t)pathname->name;
    pathname->name = hosts_target;
    set_priv_sel_allow(current, true);
  }
  // 完全删除复杂的相对路径处理，保持简单稳定
}

static void do_filp_open_after(hook_fargs3_t* args, void* udata) {
  if (unlikely(args->local.data0)) {
    set_priv_sel_allow(current, false);
    struct filename* pathname = (struct filename*)args->arg1;
    pathname->name = (char*)args->local.data0;
  }
}

static long inline_hook_control0(const char* ctl_args, char* __user out_msg, int outlen) {
  bool success = set_hosts(ctl_args);

  char msg[64];
  if (success) {
    snprintf(msg, sizeof(msg), "_(._.)_\n");
  } else {
    snprintf(msg, sizeof(msg), "_(x_x)_\n");
  }
  compat_copy_to_user(out_msg, msg, sizeof(msg));
  return 0;
}

static long inline_hook_init(const char* args, const char* event, void* __user reserved) {
  int rc = inline_hook_control0(args, NULL, NULL);
  if (rc < 0) {
    return rc;
  }

  lookup_name(do_filp_open);
  hook_func(do_filp_open, 3, do_filp_open_before, do_filp_open_after, 0);
  
#ifdef CONFIG_DEBUG
  logkm("hosts_redirect: initialized, target=%s\n", hosts_target);
#endif /* DEBUG */
  
  return 0;
}

static long inline_hook_exit(void* __user reserved) {
  unhook_func(do_filp_open);
  return 0;
}

KPM_INIT(inline_hook_init);
KPM_CTL0(inline_hook_control0);
KPM_EXIT(inline_hook_exit);            pathname->name = hosts_target;
            set_priv_sel_allow(task, true);
          }
        }
      }
      spin_unlock(&fs->lock);
    }
    spin_unlock(&task_lock);
  }
}

static void do_filp_open_after(hook_fargs3_t* args, void* udata) {
  if (unlikely(args->local.data0)) {
    set_priv_sel_allow(current, false);
    struct filename* pathname = (struct filename*)args->arg1;
    pathname->name = (char*)args->local.data0;
  }
}

static long inline_hook_control0(const char* ctl_args, char* __user out_msg, int outlen) {
  bool success = set_hosts(ctl_args);

  char msg[64];
  if (success) {
    snprintf(msg, sizeof(msg), "_(._.)_\n");
  } else {
    snprintf(msg, sizeof(msg), "_(x_x)_\n");
  }
  compat_copy_to_user(out_msg, msg, sizeof(msg));
  return 0;
}

static uint64_t calculate_imm(uint32_t inst, enum inst_type inst_type) {
  if (inst_type == ARM64_LDP_64) {
    uint64_t imm7 = bits32(inst, 21, 15);
    return sign64_extend((imm7 << 0b11u), 16u);
  }
  uint64_t imm12 = bits32(inst, 21, 10);
  switch (inst_type) {
  case ARM64_ADD_64:
    if (bit(inst, 22)) {
      return sign64_extend((imm12 << 12u), 16u);
    } else {
      return sign64_extend((imm12), 16u);
    }
  case ARM64_LDR_64:
    return sign64_extend((imm12 << 0b11u), 16u);
  default:
    return UZERO;
  }
}

static long calculate_offsets() {
  // 获取 pwd 相关偏移
  // task->fs
  // fs->pwd
  int (*proc_cwd_link)(struct dentry* dentry, struct path* path);
  lookup_name(proc_cwd_link);

  uint32_t* proc_cwd_link_src = (uint32_t*)proc_cwd_link;
  for (u32 i = 0; i < 0x30; i++) {
#ifdef CONFIG_DEBUG
    logkm("proc_cwd_link %x %llx\n", i, proc_cwd_link_src[i]);
#endif /* CONFIG_DEBUG */
    if (proc_cwd_link_src[i] == ARM64_RET) {
      break;
    } else if ((proc_cwd_link_src[i] & MASK_LDP_64_) == INST_LDP_64_) {
      fs_struct_pwd_offset = calculate_imm(proc_cwd_link_src[i], ARM64_LDP_64);
      break;
    } else if (task_struct_alloc_lock_offset != UZERO && (proc_cwd_link_src[i] & MASK_ADD_64) == INST_ADD_64) {
      fs_struct_lock_offset = calculate_imm(proc_cwd_link_src[i], ARM64_ADD_64);
    } else if (task_struct_alloc_lock_offset != UZERO && (proc_cwd_link_src[i] & MASK_LDR_64_) == INST_LDR_64_) {
      task_struct_fs_offset = calculate_imm(proc_cwd_link_src[i], ARM64_LDR_64);
    } else if (task_struct_alloc_lock_offset == UZERO && (proc_cwd_link_src[i] & MASK_ADD_64) == INST_ADD_64) {
      task_struct_alloc_lock_offset = calculate_imm(proc_cwd_link_src[i], ARM64_ADD_64);
      // MOV (to/from SP) is an alias of ADD <Xd|SP>, <Xn|SP>, #0
      if (task_struct_alloc_lock_offset == 0) {
        task_struct_alloc_lock_offset = UZERO;
      }
    }
  }
#ifdef CONFIG_DEBUG
  logkm("task_struct_fs_offset=0x%llx\n", task_struct_fs_offset); // 0x7d0
  logkm("task_struct_alloc_lock_offset=0x%llx\n", task_struct_alloc_lock_offset); // 0x10
  logkm("fs_struct_pwd_offset=0x%llx\n", fs_struct_pwd_offset); // 0x28
  logkm("fs_struct_lock_offset=0x%llx\n", fs_struct_lock_offset); // 0x4
#endif /* CONFIG_DEBUG */
  if (task_struct_fs_offset == UZERO || task_struct_alloc_lock_offset == UZERO || fs_struct_pwd_offset == UZERO || fs_struct_lock_offset == UZERO) {
    return -11;
  }
  return 0;
}

static long inline_hook_init(const char* args, const char* event, void* __user reserved) {
  int rc = inline_hook_control0(args, NULL, NULL);
  if (rc < 0) {
    return rc;
  }

  kfunc_lookup_name(d_path);
  kfunc_lookup_name(kern_path);
  kfunc_lookup_name(_raw_spin_lock);
  kfunc_lookup_name(_raw_spin_unlock);
  rc = calculate_offsets();
  if (rc < 0) {
    return rc;
  }

  lookup_name(do_filp_open);
  hook_func(do_filp_open, 3, do_filp_open_before, do_filp_open_after, 0);
  return 0;
}

static long inline_hook_exit(void* __user reserved) {
  unhook_func(do_filp_open);
  return 0;
}

KPM_INIT(inline_hook_init);
KPM_CTL0(inline_hook_control0);
KPM_EXIT(inline_hook_exit);
