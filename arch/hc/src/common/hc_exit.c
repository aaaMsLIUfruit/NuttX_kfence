/****************************************************************************
 * arch/hc/src/common/hc_exit.c
 *
 * SPDX-License-Identifier: Apache-2.0
 *
 * Licensed to the Apache Software Foundation (ASF) under one or more
 * contributor license agreements.  See the NOTICE file distributed with
 * this work for additional information regarding copyright ownership.  The
 * ASF licenses this file to you under the Apache License, Version 2.0 (the
 * "License"); you may not use this file except in compliance with the
 * License.  You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
 * WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.  See the
 * License for the specific language governing permissions and limitations
 * under the License.
 *
 ****************************************************************************/

/****************************************************************************
 * Included Files
 ****************************************************************************/

#include <nuttx/config.h>

#include <sched.h>
#include <debug.h>

#include <nuttx/arch.h>
#include <nuttx/irq.h>

#include "task/task.h"
#include "sched/sched.h"
#include "group/group.h"
#include "hc_internal.h"

/****************************************************************************
 * Public Functions
 ****************************************************************************/

/****************************************************************************
 * Name: up_exit
 *
 * Description:
 *   This function causes the currently executing task to cease
 *   to exist.  This is a special case of task_delete() where the task to
 *   be deleted is the currently executing task.  It is more complex because
 *   a context switch must be perform to the next ready to run task.
 *
 ****************************************************************************/

void up_exit(int status)
{
  struct tcb_s *tcb = this_task();

  /* Destroy the task at the head of the ready to run list. */

  nxtask_exit();

  /* Now, perform the context switch to the new ready-to-run task at the
   * head of the list.
   */

  tcb = this_task();

  /* Adjusts time slice for SCHED_RR & SCHED_SPORADIC cases */

  nxsched_resume_scheduler(tcb);
  g_running_tasks[this_cpu()] = tcb;

#ifdef CONFIG_ARCH_ADDRENV
  /* Make sure that the address environment for the previously running
   * task is closed down gracefully (data caches dump, MMU flushed) and
   * set up the address environment for the new thread at the head of
   * the ready-to-run list.
   */

  addrenv_switch(tcb);
#endif

  /* Then switch contexts */

  hc_fullcontextrestore(tcb->xcp.regs);
}
