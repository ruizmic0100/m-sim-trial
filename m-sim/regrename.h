// Physical Register File prototypes

/* SimpleScalar(TM) Tool Suite
 * Copyright (C) 1994-2003 by Todd M. Austin, Ph.D. and SimpleScalar, LLC.
 * All Rights Reserved.
 *
 * THIS IS A LEGAL DOCUMENT, BY USING SIMPLESCALAR,
 * YOU ARE AGREEING TO THESE TERMS AND CONDITIONS.
 *
 * No portion of this work may be used by any commercial entity, or for any
 * commercial purpose, without the prior, written permission of SimpleScalar,
 * LLC (info@simplescalar.com). Nonprofit and noncommercial use is permitted
 * as described below.
 *
 * 1. SimpleScalar is provided AS IS, with no warranty of any kind, express
 * or implied. The user of the program accepts full responsibility for the
 * application of the program and the use of any results.
 *
 * 2. Nonprofit and noncommercial use is encouraged. SimpleScalar may be
 * downloaded, compiled, executed, copied, and modified solely for nonprofit,
 * educational, noncommercial research, and noncommercial scholarship
 * purposes provided that this notice in its entirety accompanies all copies.
 * Copies of the modified software can be delivered to persons who use it
 * solely for nonprofit, educational, noncommercial research, and
 * noncommercial scholarship purposes provided that this notice in its
 * entirety accompanies all copies.
 *
 * 3. ALL COMMERCIAL USE, AND ALL USE BY FOR PROFIT ENTITIES, IS EXPRESSLY
 * PROHIBITED WITHOUT A LICENSE FROM SIMPLESCALAR, LLC (info@simplescalar.com).
 *
 * 4. No nonprofit user may place any restrictions on the use of this software,
 * including as modified by the user, by any other authorized user.
 *
 * 5. Noncommercial and nonprofit users may distribute copies of SimpleScalar
 * in compiled or executable form as set forth in Section 2, provided that
 * either: (A) it is accompanied by the corresponding machine-readable source
 * code, or (B) it is accompanied by a written offer, with no time limit, to
 * give anyone a machine-readable copy of the corresponding source code in
 * return for reimbursement of the cost of distribution. This written offer
 * must permit verbatim duplication by anyone, or (C) it is distributed by
 * someone who received only the executable form, and is accompanied by a
 * copy of the written offer of source code.
 *
 * 6. SimpleScalar was developed by Todd M. Austin, Ph.D. The tool suite is
 * currently maintained by SimpleScalar LLC (info@simplescalar.com). US Mail:
 * 2395 Timbercrest Court, Ann Arbor, MI 48105.
 *
 * Copyright (C) 1994-2003 by Todd M. Austin, Ph.D. and SimpleScalar, LLC.
 */


#ifndef REGRENAME_H
#define REGRENAME_H

#include<cassert>
#include"rob.h"
#include"regs.h"
#include<vector>


//holds the current state for a register
enum reg_state
{
	REG_FREE = 0,			//register is free (not allocated to any instruction)
	REG_ALLOC,			//register has been allocated, but not written to yet
	REG_WB,				//register has been written to, but not committed
	REG_ARCH			//register has been committed to the architectural state
};

//Contains a set of registers used by an instruction
//Indicates the types of each of the sources and destination
class reg_set
{
	public:
		reg_set();
		reg_type src1;		//type for source 1
		reg_type src2;		//type for source 2
		reg_type dest;		//type for the destination
		int load;		//is a load?
		int store;		//is a store?
};

//A physical register - only contains state for now

class physreg_t
{
	public:
		physreg_t();
		reg_state state;	//the state the register is currently in
		tick_t ready;		//earliest cycle in which the data will be available for read off bypass network
		tick_t spec_ready;	//earliest cycle instructions dependant on this register should issue (speculative on loads
		tick_t alloc_cycle;
};

class physical_reg_file
{
	public:
		physical_reg_file();
		void resize(int size);

		physreg_t & operator[](unsigned int index);
		const physreg_t & operator[](unsigned int index) const;

		int find_free_physreg();

		std::vector<physreg_t> data;
};

class reg_file_t
{
	public:

		int arch_reg_cnts[4];
		reg_file_t();
		void resize(int size);

		int find_free_physreg(reg_type type);

		unsigned int size();

		physreg_t & reg_file_access(int index,reg_type type);

		// Allocates a physical register to the specified ROB entry
		int alloc_physreg(ROB_entry* rob_entry,tick_t sim_cycle,std::vector<int> & rename_table, int display_context_id);

		//Returns the set of register types used by a specific operation
		//This doesn't need to be in reg_file_t, but is for isolation purposes
		void get_reg_set(reg_set* my_regs, md_opcode op);

		physical_reg_file intregs,fpregs;
};


#endif
