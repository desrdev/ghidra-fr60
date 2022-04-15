/* ###
 * IP: GHIDRA
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 * 
 *      http://www.apache.org/licenses/LICENSE-2.0
 * 
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package fr60;

import java.io.IOException;
import java.io.InputStream;
import java.util.*;

import ghidra.app.util.Option;
import ghidra.app.util.bin.BinaryReader;
import ghidra.app.util.bin.ByteProvider;
import ghidra.app.util.importer.MessageLog;
import ghidra.app.util.opinion.AbstractLibrarySupportLoader;
import ghidra.app.util.opinion.LoadSpec;
import ghidra.framework.model.DomainObject;
import ghidra.framework.store.LockException;
import ghidra.program.flatapi.FlatProgramAPI;
import ghidra.program.model.address.AddressOverflowException;
import ghidra.program.model.lang.LanguageCompilerSpecPair;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.Memory;
import ghidra.program.model.mem.MemoryAccessException;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.model.mem.MemoryConflictException;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

/**
 * TODO: Provide class-level documentation that describes what this loader does.
 */
public class DVRPFirmwareLoader extends AbstractLibrarySupportLoader {

	private MB91302AMemRegion[] MEM_REGIONS;

	@Override
	public String getName() {

		// TODO: Name the loader.  This name must match the name of the loader in the .opinion 
		// files.

		return "DVRP Firmware Loader (UDM)";
	}

	@Override
	public Collection<LoadSpec> findSupportedLoadSpecs(ByteProvider provider) throws IOException {
		List<LoadSpec> loadSpecs = new ArrayList<>();
		
		byte[] dvrpHeader = "DVRP".getBytes();
		
		byte[] fileHeader = provider.readBytes(0, 4);
		
		if (Arrays.equals(dvrpHeader, fileHeader)) {
			loadSpecs.add(new LoadSpec(this, 0, new LanguageCompilerSpecPair("fr60:BE:16:default", "fcc911"), true));
		}

		return loadSpecs;
	}

	@Override
	protected void load(ByteProvider provider, LoadSpec loadSpec, List<Option> options,
			Program program, TaskMonitor monitor, MessageLog log)
			throws CancelledException, IOException {
		
		BinaryReader reader = new BinaryReader(provider, true).asBigEndian();
		FlatProgramAPI api = new FlatProgramAPI(program, monitor);
		Memory mem = program.getMemory();
		
		int ram_base = 0x10000000;
		int ram_size = 0x01000000;
				
		int rom_lower_size = reader.readInt(0x10);
		int rom_lower_offset = reader.readInt(0x18);
		int rom_upper_size = reader.readInt(0x24);
		int rom_upper_offset = reader.readInt(0x30);
		int rom_entry_point = reader.readInt(0x40);
		
		
		byte lowerRomBytes[] = reader.readByteArray(rom_lower_offset, rom_lower_size);
		byte romUpperBytes[] = reader.readByteArray(rom_upper_offset + rom_lower_offset + 24, rom_upper_size - 24);
		
		// Only 0xF0000 -> 0xDFFFF is accessable on external bus
		byte accessableLowerBytes[] = Arrays.copyOfRange(lowerRomBytes, 0x40000, rom_lower_size);

        try {
    		MemoryBlock block = program.getMemory().createInitializedBlock(
    				"External RAM", 
    				program.getAddressFactory().getDefaultAddressSpace().getAddress(ram_base), 
    				ram_size, 
    				(byte)0x00, 
    				monitor, 
    				false
    		);
    		
    		block.setRead(true);
    		block.setWrite(true);
    		block.setExecute(true);
    		
        	block = mem.createInitializedBlock("ROM Lower", program.getAddressFactory().getDefaultAddressSpace().getAddress(0x40000), 0xA0000, (byte)0x00, monitor, false);
        	block.setRead(true);
        	block.setWrite(true);
        	block.setExecute(true);
        	
        	block = mem.createInitializedBlock("Internal ROM", program.getAddressFactory().getDefaultAddressSpace().getAddress(0xFF000), 0x10000, (byte)0x00, monitor, false);
        	block.setRead(true);
        	block.setWrite(false);
        	block.setExecute(true);

    		// From Data sheet
        	block = mem.createUninitializedBlock("Byte I/O", api.toAddr(0x0), 0x100, false);
        	block.setRead(true);
        	block.setWrite(true);
        	block.setVolatile(true);
        	block = mem.createUninitializedBlock("Direct I/O", api.toAddr(0x100), 0x300, false);
        	block.setRead(true);
        	block.setWrite(true);
        	block.setVolatile(true);
        	block = mem.createUninitializedBlock("I/O", api.toAddr(0x400), 0xFC00, false);
        	block.setRead(true);
        	block.setWrite(true);
        	block.setVolatile(true);
        	block = mem.createUninitializedBlock("Internal RAM", api.toAddr(0x3F000), 0x1000, false);
        	block.setRead(true);
        	block.setWrite(true);
        	block.setExecute(true);

        	
        	// PSX RE
        	block = mem.createUninitializedBlock("SPEED", api.toAddr(0x1010000), 0x10000, false);
        	block.setRead(true);
        	block.setWrite(true);
        	block.setVolatile(true);
        	block = mem.createUninitializedBlock("Unk 16bit", api.toAddr(0x1020000), 0x10000, false);
        	block.setRead(true);
        	block.setWrite(true);
        	block.setVolatile(true);
        	block = mem.createUninitializedBlock("SPEED 8bit", api.toAddr(0x1040000), 0x20000, false);
        	block.setRead(true);
        	block.setWrite(true);
        	block.setVolatile(true);
        	block = mem.createUninitializedBlock("ATAH", api.toAddr(0x2400000), 0x400000, false);
        	block.setRead(true);
        	block.setWrite(true);
        	block.setVolatile(true);
        	block = mem.createUninitializedBlock("ATAL", api.toAddr(0x2000000), 0x400000, false);
        	block.setRead(true);
        	block.setWrite(true);
        	block.setVolatile(true);
        	block = mem.createUninitializedBlock("CPLD", api.toAddr(0x1070000), 0x10000, false);
        	block.setRead(true);
        	block.setWrite(true);
        	block.setVolatile(true);
        	
        	mem.setBytes(api.toAddr(0x40000), accessableLowerBytes);
        	mem.setBytes(api.toAddr(0x10000000), romUpperBytes);
        	
        	api.addEntryPoint(api.toAddr(rom_entry_point));
        	api.disassemble(api.toAddr(rom_entry_point));
        	api.createFunction(api.toAddr(rom_entry_point), "_rom_entry");
		} catch (LockException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (MemoryConflictException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (AddressOverflowException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (CancelledException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (IllegalArgumentException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (MemoryAccessException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
	}

	@Override
	public List<Option> getDefaultOptions(ByteProvider provider, LoadSpec loadSpec,
			DomainObject domainObject, boolean isLoadIntoProgram) {
		List<Option> list =
			super.getDefaultOptions(provider, loadSpec, domainObject, isLoadIntoProgram);

		// TODO: If this loader has custom options, add them to 'list'
		list.add(new Option("Option name goes here", "Default option value goes here"));

		return list;
	}

	@Override
	public String validateOptions(ByteProvider provider, LoadSpec loadSpec, List<Option> options, Program program) {

		// TODO: If this loader has custom options, validate them here.  Not all options require
		// validation.

		return super.validateOptions(provider, loadSpec, options, program);
	}
	
	private static class MB91302AMemRegion {
		String name;
		int addr;
		int size;
		boolean read;
		boolean write;
		boolean execute;
		private MB91302AMemRegion(String name, int addr, int size, boolean read, boolean write, boolean execute) {
			this.name = name;
			this.addr = addr;
			this.size = size;
			this.read = read;
			this.write = write;
			this.execute = execute;
		}
	
	}
}
