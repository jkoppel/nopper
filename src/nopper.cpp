/*
 * Copyright 2011 James Koppel
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
 
/*
 * Nopper uses breakpoints to simulate the effect of replacing
 * assembly instructions with NOPs.
 */

#include <ida.hpp>
#include <idp.hpp>
#include <dbg.hpp>
#include <expr.hpp>
#include <loader.hpp>
#include <netnode.hpp>

#include <set>
#include <map>

using namespace std;

set<ea_t> disabled_addrs;
map<ea_t, ea_t> skip_cache;

bgcolor_t disabled_col = 0x00222222;

const char* node_name = "$ nopper addresses";

netnode *prim_node = NULL;

//--------------------------------------------------------------------------
static int idaapi dbg_callback(void * /*user_data*/, int notification_code, va_list va)
{
  if( notification_code == dbg_bpt) {
	thid_t tid = va_arg(va, thid_t);
	ea_t addr  = va_arg(va, ea_t);

	if(disabled_addrs.count(addr)) {
		ea_t targ_addr = addr;

		if(skip_cache.count(addr)) {
			targ_addr = skip_cache[addr];
		} else {
			do {
				targ_addr = next_not_tail(targ_addr);
			} while(disabled_addrs.count(targ_addr));
			skip_cache[addr] = targ_addr;
		}
		regval_t v;
		v.rvtype = RVT_INT;
		v.ival = targ_addr;
		bool r1 = request_set_reg_val("EIP", &v);
		bool r2 = request_continue_process();
		bool r3 = run_requests();
		if(r1 && r2 && r3) {
			//msg("Skipping past instruction at %a to %a.\n", addr, targ_addr);
		} else {
			//msg("Failed to skip past instruction at %a.\n", addr);
		}
	}
  }
  return 0;
}

static int idaapi idp_callback(void * /*user_data*/, int notification_code, va_list va) {

	if(notification_code == processor_t::get_bg_color) { 
		ea_t addr = va_arg(va, ea_t);
		bgcolor_t *col  = va_arg(va, bgcolor_t*);
		
		if(disabled_addrs.count(addr)) {
			*col = disabled_col;
			return 2;
		} else {
			return 1;
		}
	} else {
	  return 0;
  }
}

void toggle_address(ea_t ea) {
  if(disabled_addrs.count(ea))
	  del_bpt(ea);
  else
	  add_bpt(ea);

  if(!disabled_addrs.count(ea)) {
	  disabled_addrs.insert(ea);
	  prim_node->altset(ea,1);
	  //msg("Disabling address %a.\n", ea);
  } else {
	  disabled_addrs.erase(disabled_addrs.find(ea));
	  prim_node->altdel(ea);
	  //msg("Enabling address %a\n", ea);
  }
}

void toggle_segment(ea_t start, ea_t end) {

  if(disabled_addrs.count(start))
	  del_bpt(start);
  else
	  add_bpt(start);

  bool bpt_set = false;

  for(ea_t ea = start; ea < end; ea = next_not_tail(ea)) {
	if(!disabled_addrs.count(ea)) {
		disabled_addrs.insert(ea);
		prim_node->altset(ea, 1);
		//msg("Disabling address %a.\n", ea);

		if(!bpt_set) {
			add_bpt(ea);
			bpt_set = true;
		}
	} else {
		del_bpt(ea);
		bpt_set = false;
		prim_node->altdel(ea);
		disabled_addrs.erase(disabled_addrs.find(ea));
		//msg("Enabling address %a\n", ea);
	}
  }
}

//--------------------------------------------------------------------------
void idaapi run(int /*arg*/)
{
  ea_t start, end;
  ea_t scr = get_screen_ea();

  if(read_selection(&start, &end)) {
	toggle_segment(start, end);
  } else if(scr != BADADDR) {
	toggle_address(scr);
  }
  skip_cache.clear();
}

//--------------------------------------------------------------------------
int idaapi init(void)
{
  if(!hook_to_notification_point(HT_DBG, dbg_callback, NULL)) {
	  msg("Nopper failed to hook to debugger; plugin not loaded.");
	  return PLUGIN_SKIP;
  }

  if(!hook_to_notification_point(HT_IDP, idp_callback, NULL)) {
	unhook_from_notification_point(HT_DBG, dbg_callback, NULL);
	msg("Nopper failed to hook to IDA events; plugin not loaded.");
    return PLUGIN_SKIP;
  }
  
  prim_node = new netnode(node_name, 0, true);
		
  for(nodeidx_t idx = prim_node->alt1st(); idx != BADNODE; idx = prim_node->altnxt(idx)) {
	  disabled_addrs.insert(idx);
  }

  return PLUGIN_KEEP;
}

//--------------------------------------------------------------------------
void idaapi term(void)
{
  // just to be safe
  unhook_from_notification_point(HT_DBG, dbg_callback, NULL);
  unhook_from_notification_point(HT_IDP, idp_callback, NULL);
  disabled_addrs.clear();
}

//--------------------------------------------------------------------------
char wanted_name[] = "NOP out ASM";
char wanted_hotkey[] = "Alt+F2";


//--------------------------------------------------------------------------
//
//      PLUGIN DESCRIPTION BLOCK
//
//--------------------------------------------------------------------------
plugin_t PLUGIN =
{
  IDP_INTERFACE_VERSION,
  PLUGIN_DRAW | PLUGIN_PROC, // plugin flags
  init,                 // initialize

  term,                 // terminate. this pointer may be NULL.

  run,                  // invoke plugin

  wanted_name,          // long comment about the plugin
                        // it could appear in the status line
                        // or as a hint

  wanted_name,          // multiline help about the plugin

  wanted_name,          // the preferred short name of the plugin
  wanted_hotkey         // the preferred hotkey to run the plugin
};
