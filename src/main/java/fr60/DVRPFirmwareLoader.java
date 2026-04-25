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
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.List;

import ghidra.app.util.bin.BinaryReader;
import ghidra.app.util.bin.ByteProvider;
import ghidra.app.util.opinion.AbstractLibrarySupportLoader;
import ghidra.app.util.opinion.LoadSpec;
import ghidra.app.util.opinion.Loader.ImporterSettings;
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
 * Loads DVRP UDM containers and raw flash images into the FR60 memory map.
 */
public class DVRPFirmwareLoader extends AbstractLibrarySupportLoader {

	private static final byte[] UDM_MAGIC = "DVRP".getBytes(StandardCharsets.US_ASCII);
	private static final long RAW_FLASH_MAGIC = 0x46d271a4L;
	private static final long FIRMWARE_HEADER_MAGIC = 0x84271fb1L;

	private static final LanguageCompilerSpecPair LANGUAGE_COMPILER_SPEC =
		new LanguageCompilerSpecPair("fr60:BE:16:default", "fcc911");

	private static final long FLASH_BASE = 0x00400000L;
	private static final long EXTERNAL_RAM_BASE = 0x10000000L;
	private static final long EXTERNAL_RAM_SIZE = 0x01000000L;

	private static final long ROM_LOWER_BASE = 0x00040000L;
	private static final int ROM_LOWER_VISIBLE_OFFSET = 0x00040000;
	private static final int ROM_LOWER_VISIBLE_SIZE = 0x000a0000;
	private static final int ROM_LOWER_VISIBLE_END =
		ROM_LOWER_VISIBLE_OFFSET + ROM_LOWER_VISIBLE_SIZE;
	private static final long INTERNAL_ROM_BASE = 0x000ff000L;
	private static final long INTERNAL_ROM_SIZE = 0x00010000L;

	private static final int FLASH_HEADER_SIZE = 0x20;
	private static final int FIRMWARE_HEADER_SIZE = 0x18;

	@Override
	public String getName() {
		return "DVRP Firmware Loader";
	}

	@Override
	public Collection<LoadSpec> findSupportedLoadSpecs(ByteProvider provider) throws IOException {
		List<LoadSpec> loadSpecs = new ArrayList<>();

		if (isUdm(provider) || tryReadRawFlashImage(provider) != null) {
			loadSpecs.add(new LoadSpec(this, 0, LANGUAGE_COMPILER_SPEC, true));
		}

		return loadSpecs;
	}

	@Override
	protected void load(Program program, ImporterSettings settings)
			throws CancelledException, IOException {
		ByteProvider provider = settings.provider();
		TaskMonitor monitor = settings.monitor();
		FlatProgramAPI api = new FlatProgramAPI(program, monitor);
		Memory mem = program.getMemory();

		try {
			if (isUdm(provider)) {
				loadUdm(program, provider, api, mem, monitor);
				return;
			}

			RawFlashImage rawFlashImage = tryReadRawFlashImage(provider);
			if (rawFlashImage != null) {
				loadRawFlash(program, provider, rawFlashImage, api, mem, monitor);
				return;
			}

			throw new IOException("Unsupported DVRP image format");
		}
		catch (LockException e) {
			throw new IOException("Failed to create DVRP memory map", e);
		}
		catch (MemoryConflictException e) {
			throw new IOException("DVRP memory block layout overlaps existing memory", e);
		}
		catch (AddressOverflowException e) {
			throw new IOException("DVRP memory map contains an invalid address", e);
		}
		catch (IllegalArgumentException e) {
			throw new IOException("DVRP image contains invalid address data", e);
		}
		catch (MemoryAccessException e) {
			throw new IOException("Failed to write DVRP image bytes into memory", e);
		}
	}

	private boolean isUdm(ByteProvider provider) throws IOException {
		if (provider.length() < UDM_MAGIC.length) {
			return false;
		}
		return Arrays.equals(UDM_MAGIC, provider.readBytes(0, UDM_MAGIC.length));
	}

	private void loadUdm(Program program, ByteProvider provider, FlatProgramAPI api, Memory mem,
			TaskMonitor monitor)
			throws IOException, LockException, MemoryConflictException, AddressOverflowException,
			MemoryAccessException, CancelledException {
		BinaryReader reader = new BinaryReader(provider, false);

		long romLowerSize = reader.readUnsignedInt(0x10);
		long romLowerOffset = reader.readUnsignedInt(0x18);
		long romUpperSize = reader.readUnsignedInt(0x24);
		long romUpperOffset = reader.readUnsignedInt(0x30);
		long romEntryPoint = reader.readUnsignedInt(0x40);

		byte[] lowerRomBytes = readBytes(reader, romLowerOffset, romLowerSize, "UDM lower ROM");
		if (lowerRomBytes.length < ROM_LOWER_VISIBLE_END) {
			throw new IOException("UDM lower ROM is too small to populate the visible ROM window");
		}

		if (romUpperSize < FIRMWARE_HEADER_SIZE) {
			throw new IOException("UDM upper ROM size is smaller than a firmware header");
		}

		byte[] romUpperBytes = readBytes(reader,
			romUpperOffset + romLowerOffset + FIRMWARE_HEADER_SIZE,
			romUpperSize - FIRMWARE_HEADER_SIZE, "UDM upper ROM payload");
		byte[] visibleLowerBytes =
			Arrays.copyOfRange(lowerRomBytes, ROM_LOWER_VISIBLE_OFFSET, ROM_LOWER_VISIBLE_END);

		createHardwareBlocks(mem, api, monitor);
		createUdmRomBlocks(mem, api, monitor);

		mem.setBytes(api.toAddr(ROM_LOWER_BASE), visibleLowerBytes);
		mem.setBytes(api.toAddr(EXTERNAL_RAM_BASE), romUpperBytes);

		markEntryPoint(api, romEntryPoint, "_rom_entry");
	}

	private RawFlashImage tryReadRawFlashImage(ByteProvider provider) throws IOException {
		if (provider.length() < FLASH_HEADER_SIZE) {
			return null;
		}

		BinaryReader reader = new BinaryReader(provider, false);
		DvrpFlashHeader flashHeader = readFlashHeader(reader);
		if (flashHeader.magic != RAW_FLASH_MAGIC) {
			return null;
		}

		long firmAOffset = toFlashFileOffset(flashHeader.firmAPtr, provider.length(), "firmA");
		DvrpFirmwareHeader firmAHeader = readFirmwareHeader(reader, firmAOffset, "firmA");
		validateExternalRamRange(firmAHeader.copyToAddr, firmAHeader.copySize,
			"firmA payload destination");

		return new RawFlashImage(flashHeader, firmAHeader, firmAOffset);
	}

	private void loadRawFlash(Program program, ByteProvider provider, RawFlashImage rawFlashImage,
			FlatProgramAPI api, Memory mem, TaskMonitor monitor)
			throws IOException, LockException, MemoryConflictException, AddressOverflowException,
			MemoryAccessException, CancelledException {
		createHardwareBlocks(mem, api, monitor);
		createFlashBlock(mem, api, monitor, provider.length());

		byte[] flashBytes = readProviderBytes(provider, 0, provider.length(), "raw flash image");
		mem.setBytes(api.toAddr(FLASH_BASE), flashBytes);

		long firmAPayloadOffset = rawFlashImage.firmAOffset + rawFlashImage.firmAHeader.headerLen;
		byte[] firmABytes = readProviderBytes(provider, firmAPayloadOffset,
			rawFlashImage.firmAHeader.copySize, "firmA payload");
		mem.setBytes(api.toAddr(rawFlashImage.firmAHeader.copyToAddr), firmABytes);

		markEntryPoint(api, rawFlashImage.firmAHeader.entryPoint, "_firmA_entry");
	}

	private DvrpFlashHeader readFlashHeader(BinaryReader reader) throws IOException {
		validateRange(reader, 0, FLASH_HEADER_SIZE, "raw flash header");

		return new DvrpFlashHeader(
			reader.readUnsignedInt(0x00),
			reader.readUnsignedInt(0x04),
			reader.readUnsignedShort(0x08),
			reader.readUnsignedShort(0x0a),
			reader.readUnsignedShort(0x0c),
			reader.readUnsignedShort(0x0e),
			reader.readUnsignedInt(0x10),
			reader.readUnsignedInt(0x14),
			reader.readUnsignedInt(0x18),
			reader.readUnsignedInt(0x1c));
	}

	private DvrpFirmwareHeader readFirmwareHeader(BinaryReader reader, long headerOffset,
			String description) throws IOException {
		validateRange(reader, headerOffset, FIRMWARE_HEADER_SIZE, description + " header");

		long magic = reader.readUnsignedInt(headerOffset + 0x00);
		if (magic != FIRMWARE_HEADER_MAGIC) {
			throw new IOException(description + " header magic mismatch");
		}

		long headerLen = reader.readUnsignedInt(headerOffset + 0x04);
		long copyToAddr = reader.readUnsignedInt(headerOffset + 0x08);
		long copySize = reader.readUnsignedInt(headerOffset + 0x0c);
		long checksum = reader.readUnsignedInt(headerOffset + 0x10);
		long entryPoint = reader.readUnsignedInt(headerOffset + 0x14);

		if (headerLen < FIRMWARE_HEADER_SIZE) {
			throw new IOException(description + " header length is too small");
		}

		validateRange(reader, headerOffset + headerLen, copySize, description + " payload");

		return new DvrpFirmwareHeader(magic, headerLen, copyToAddr, copySize, checksum,
			entryPoint);
	}

	private long toFlashFileOffset(long flashAddress, long fileLength, String description)
			throws IOException {
		if (flashAddress < FLASH_BASE) {
			throw new IOException(description + " pointer is below the flash base");
		}

		long fileOffset = flashAddress - FLASH_BASE;
		if (fileOffset >= fileLength) {
			throw new IOException(description + " pointer is outside the flash image");
		}

		return fileOffset;
	}

	private void validateExternalRamRange(long address, long size, String description)
			throws IOException {
		long end = address + size;
		if (end < address || address < EXTERNAL_RAM_BASE ||
				end > EXTERNAL_RAM_BASE + EXTERNAL_RAM_SIZE) {
			throw new IOException(description + " does not fit in external RAM");
		}
	}

	private void validateRange(BinaryReader reader, long offset, long size, String description)
			throws IOException {
		int length = toInt(size, description);
		if (!reader.isValidRange(offset, length)) {
			throw new IOException(description + " is outside the image");
		}
	}

	private byte[] readBytes(BinaryReader reader, long offset, long size, String description)
			throws IOException {
		validateRange(reader, offset, size, description);
		return reader.readByteArray(offset, toInt(size, description));
	}

	private byte[] readProviderBytes(ByteProvider provider, long offset, long size,
			String description) throws IOException {
		int length = toInt(size, description);
		if (offset < 0 || offset + length > provider.length()) {
			throw new IOException(description + " is outside the image");
		}
		return provider.readBytes(offset, length);
	}

	private int toInt(long value, String description) throws IOException {
		if (value < 0 || value > Integer.MAX_VALUE) {
			throw new IOException(description + " exceeds Java array limits");
		}
		return (int) value;
	}

	private void createHardwareBlocks(Memory mem, FlatProgramAPI api, TaskMonitor monitor)
			throws LockException, MemoryConflictException, AddressOverflowException,
			CancelledException {
		MemoryBlock block = createInitializedBlock(mem, api, monitor, "External RAM",
			EXTERNAL_RAM_BASE, EXTERNAL_RAM_SIZE, true, true, true, false);
		block = createInitializedBlock(mem, api, monitor, "Internal ROM", INTERNAL_ROM_BASE,
			INTERNAL_ROM_SIZE, true, false, true, false);

		block = createUninitializedBlock(mem, api, "Byte I/O", 0x00000000L, 0x100, true, true,
			false, true);
		block = createUninitializedBlock(mem, api, "Direct I/O", 0x00000100L, 0x300, true, true,
			false, true);
		block = createUninitializedBlock(mem, api, "I/O", 0x00000400L, 0xfc00, true, true,
			false, true);
		block = createUninitializedBlock(mem, api, "Internal RAM", 0x0003f000L, 0x1000, true,
			true, true, false);

		block = createUninitializedBlock(mem, api, "SPEED", 0x01010000L, 0x10000, true, true,
			false, true);
		block = createUninitializedBlock(mem, api, "Unk 16bit", 0x01020000L, 0x10000, true,
			true, false, true);
		block = createUninitializedBlock(mem, api, "SPEED 8bit", 0x01040000L, 0x20000, true,
			true, false, true);
		block = createUninitializedBlock(mem, api, "CPLD", 0x01070000L, 0x10000, true, true,
			false, true);
		block = createUninitializedBlock(mem, api, "ATAL", 0x02000000L, 0x400000, true, true,
			false, true);
		createUninitializedBlock(mem, api, "ATAH", 0x02400000L, 0x400000, true, true, false,
			true);
	}

	private void createUdmRomBlocks(Memory mem, FlatProgramAPI api, TaskMonitor monitor)
			throws LockException, MemoryConflictException, AddressOverflowException,
			CancelledException {
		createInitializedBlock(mem, api, monitor, "ROM Lower", ROM_LOWER_BASE,
			ROM_LOWER_VISIBLE_SIZE, true, false, true, false);
	}

	private void createFlashBlock(Memory mem, FlatProgramAPI api, TaskMonitor monitor,
			long flashSize)
			throws LockException, MemoryConflictException, AddressOverflowException,
			CancelledException {
		createInitializedBlock(mem, api, monitor, "Flash ROM", FLASH_BASE, flashSize, true,
			false, true, false);
	}

	private MemoryBlock createInitializedBlock(Memory mem, FlatProgramAPI api, TaskMonitor monitor,
			String name, long address, long size, boolean read, boolean write, boolean execute,
			boolean isVolatile)
			throws LockException, MemoryConflictException, AddressOverflowException,
			CancelledException {
		MemoryBlock block = mem.createInitializedBlock(name, api.toAddr(address), size, (byte) 0x00,
			monitor, false);
		block.setRead(read);
		block.setWrite(write);
		block.setExecute(execute);
		block.setVolatile(isVolatile);
		return block;
	}

	private MemoryBlock createUninitializedBlock(Memory mem, FlatProgramAPI api, String name,
			long address, long size, boolean read, boolean write, boolean execute,
			boolean isVolatile)
			throws LockException, MemoryConflictException, AddressOverflowException {
		MemoryBlock block = mem.createUninitializedBlock(name, api.toAddr(address), size, false);
		block.setRead(read);
		block.setWrite(write);
		block.setExecute(execute);
		block.setVolatile(isVolatile);
		return block;
	}

	private void markEntryPoint(FlatProgramAPI api, long entryPoint, String functionName)
			throws CancelledException {
		api.addEntryPoint(api.toAddr(entryPoint));
		api.disassemble(api.toAddr(entryPoint));
		api.createFunction(api.toAddr(entryPoint), functionName);
	}

	private static class DvrpFlashHeader {
		private final long magic;
		private final long asr;
		private final int awr;
		private final int mcra;
		private final int rcr;
		private final int iowr;
		private final long firmAPtr;
		private final long firmAMetaPtr;
		private final long firmBPtr;
		private final long firmBMetaPtr;

		private DvrpFlashHeader(long magic, long asr, int awr, int mcra, int rcr, int iowr,
				long firmAPtr, long firmAMetaPtr, long firmBPtr, long firmBMetaPtr) {
			this.magic = magic;
			this.asr = asr;
			this.awr = awr;
			this.mcra = mcra;
			this.rcr = rcr;
			this.iowr = iowr;
			this.firmAPtr = firmAPtr;
			this.firmAMetaPtr = firmAMetaPtr;
			this.firmBPtr = firmBPtr;
			this.firmBMetaPtr = firmBMetaPtr;
		}
	}

	private static class DvrpFirmwareHeader {
		private final long magic;
		private final long headerLen;
		private final long copyToAddr;
		private final long copySize;
		private final long checksum;
		private final long entryPoint;

		private DvrpFirmwareHeader(long magic, long headerLen, long copyToAddr, long copySize,
				long checksum, long entryPoint) {
			this.magic = magic;
			this.headerLen = headerLen;
			this.copyToAddr = copyToAddr;
			this.copySize = copySize;
			this.checksum = checksum;
			this.entryPoint = entryPoint;
		}
	}

	private static class RawFlashImage {
		private final DvrpFlashHeader flashHeader;
		private final DvrpFirmwareHeader firmAHeader;
		private final long firmAOffset;

		private RawFlashImage(DvrpFlashHeader flashHeader, DvrpFirmwareHeader firmAHeader,
				long firmAOffset) {
			this.flashHeader = flashHeader;
			this.firmAHeader = firmAHeader;
			this.firmAOffset = firmAOffset;
		}
	}
}
