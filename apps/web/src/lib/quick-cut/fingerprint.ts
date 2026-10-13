import { sha256 } from '@noble/hashes/sha2';
import { bytesToHex } from '@noble/hashes/utils';

// Hash every byte without buffering the entire source in memory. Sampled hashes
// cannot safely validate cached transcripts or relinked media.
export async function createHash(
	file: File,
	signal?: AbortSignal
): Promise<string> {
	const hash = sha256.create();
	const chunkSize = 256 * 1024;
	for (let offset = 0; offset < file.size; offset += chunkSize) {
		signal?.throwIfAborted();
		const chunk = await file.slice(offset, offset + chunkSize).arrayBuffer();
		signal?.throwIfAborted();
		hash.update(new Uint8Array(chunk));
	}
	signal?.throwIfAborted();
	return bytesToHex(hash.digest());
}
