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
// Loads a dumped DVRP internal mask ROM into the existing Internal ROM block.
//@category Memory

import java.io.File;
import java.nio.file.Files;

import ghidra.app.script.GhidraScript;
import ghidra.program.model.mem.MemoryBlock;

public class LoadInternalMaskRomScript extends GhidraScript {

	private static final long INTERNAL_ROM_BASE = 0x000ff000L;
	private static final long INTERNAL_ROM_SIZE = 0x00010000L;
	private static final String INTERNAL_ROM_BLOCK_NAME = "Internal ROM";

	@Override
	protected void run() throws Exception {
		MemoryBlock internalRom = currentProgram.getMemory().getBlock(INTERNAL_ROM_BLOCK_NAME);
		if (internalRom == null) {
			popup("Current program does not contain an Internal ROM memory block.");
			return;
		}

		if (internalRom.getStart().getOffset() != INTERNAL_ROM_BASE ||
				internalRom.getSize() != INTERNAL_ROM_SIZE) {
			popup(String.format(
				"Internal ROM block has unexpected layout: start=%s size=0x%x",
				internalRom.getStart(), internalRom.getSize()));
			return;
		}

		File romFile = askFile("Select Internal Mask ROM Dump", "Load");
		byte[] romBytes = Files.readAllBytes(romFile.toPath());

		if (romBytes.length == 0) {
			popup("Selected ROM dump is empty.");
			return;
		}

		if (romBytes.length > INTERNAL_ROM_SIZE) {
			popup(String.format(
				"ROM dump is too large: 0x%x bytes, expected at most 0x%x bytes.",
				romBytes.length, INTERNAL_ROM_SIZE));
			return;
		}

		int tx = currentProgram.startTransaction("Load Internal Mask ROM");
		boolean success = false;
		try {
			currentProgram.getMemory().setBytes(toAddr(INTERNAL_ROM_BASE), romBytes);
			success = true;
		}
		finally {
			currentProgram.endTransaction(tx, success);
		}

		printf("Loaded 0x%x bytes from %s into %s at %s\n", romBytes.length,
			romFile.getName(), INTERNAL_ROM_BLOCK_NAME, toAddr(INTERNAL_ROM_BASE));
	}
}
