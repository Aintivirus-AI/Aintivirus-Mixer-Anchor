import base58 from "bs58";
import * as snarkjs from "snarkjs";
import crypto from 'crypto';
import fs from "fs";
import { PublicKey } from "@solana/web3.js";
import { BigNumberish } from 'ethers'
import { buildBn12381, utils, buildBn128 } from "ffjavascript";
import { poseidon4, poseidon2 } from "poseidon-lite";

type ParsedProofInputs = {
    publicInputs: Uint8Array[]; // 32-byte inputs
    nullifierHash: bigint;      // as bigint
    mintPubkey: string;         // base58 string
    amount: bigint;             // from 8 bytes
    mode: number;               // from 1 byte
};


export default class ZkSolana {
    // Function to generate a proof
    static async generateProof(secret: string, nullifier: string, amount: string, commitment: string, mode: number): Promise<{
        proof: { pi_a: string[]; pi_b: string[][]; pi_c: string[] };
        publicSignals: bigint[];
    }> {
        const circuitWasmPath = "circuit/proof.wasm";
        const zkeyPath = "circuit/proof_final.zkey";

        const input = {
            secret,
            nullifier,
            amount,
            commitment,
            mode
        };
        const { proof, publicSignals } = await snarkjs.groth16.fullProve(
            input,
            circuitWasmPath,
            zkeyPath
        );
        return { proof, publicSignals };
    }

    static generateSecretAndNullifier(): { secret: bigint; nullifier: bigint } {
        const FIELD_PRIME = BigInt('21888242871839275222246405745257275088548364400416034343698204186575808495617');
        try {
            // Generate 32-byte random values (256 bits)
            const secretBytes = crypto.randomBytes(32);
            const nullifierBytes = crypto.randomBytes(32);

            // Convert to bigints and reduce modulo the BN254 scalar field prime
            const secret = BigInt('0x' + secretBytes.toString('hex')) % FIELD_PRIME;
            const nullifier = BigInt('0x' + nullifierBytes.toString('hex')) % FIELD_PRIME;

            return { secret, nullifier };
        } catch (error) {
            throw new Error(`Failed to generate random secret and nullifier: ${(error as Error).message}`);
        }
    }

    static to32ByteBuffer(bigInt) {
        const hexString = bigInt.toString(16).padStart(64, '0');
        const buffer = Buffer.from(hexString, "hex");
        return buffer;
    }

    static async offchainVerifyProof(
        zkData: {
            proof: {
                pi_a: string[];
                pi_b: string[][];
                pi_c: string[];
            };
            publicSignals: bigint[]
        }
    ): Promise<boolean> {
        try {
            const { proof, publicSignals } = zkData;
            const vKey = JSON.parse(fs.readFileSync("circuit/proof_verification_key.json").toString());
            const valid = await snarkjs.groth16.verify(vKey, publicSignals.map(s => s.toString()), proof);
            return valid;
        } catch (error) {
            console.error(error);
            return false;
        }
    }

    static bigintToU8Array32(value: bigint): number[] {
        const bytes = new Uint8Array(32);
        const hex = value.toString(16).padStart(64, "0"); // 64 hex chars = 32 bytes
        for (let i = 0; i < 32; i++) {
            bytes[i] = parseInt(hex.slice((31 - i) * 2, (32 - i) * 2), 16);
        }
        return Array.from(bytes);
    }

    /**
     * ChatGPT suggested code start
     */
    static bigIntTo32BytesLE(bi: bigint): Uint8Array {
        const hex = bi.toString(16).padStart(64, "0"); // 32 bytes = 64 hex chars
        const buf = Buffer.from(hex, "hex");
        return new Uint8Array(buf.reverse()); // Solana prefers little-endian
    }

    static packG1(g1: [bigint, bigint]): Uint8Array {
        return new Uint8Array([
            ...ZkSolana.bigIntTo32BytesLE(g1[0]), // x
            ...ZkSolana.bigIntTo32BytesLE(g1[1])  // y
        ]);
    }

    static packG2(g2: [[bigint, bigint], [bigint, bigint]]): Uint8Array {
        return new Uint8Array([
            ...ZkSolana.bigIntTo32BytesLE(g2[0][0]), // x0
            ...ZkSolana.bigIntTo32BytesLE(g2[0][1]), // x1
            ...ZkSolana.bigIntTo32BytesLE(g2[1][0]), // y0
            ...ZkSolana.bigIntTo32BytesLE(g2[1][1]), // y1
        ]);
    }

    // static packPublicInputs(inputs: bigint[]): Uint8Array {
    //     return new Uint8Array(
    //         inputs.flatMap(bi => Array.from(ZkSolana.bigIntTo32BytesLE(bi)))
    //     );
    // }

    static packPublicInputs(inputs: bigint[]): Uint8Array {
        const flattened = inputs.reduce((acc, bi) => {
            acc.push(...Array.from(ZkSolana.bigIntTo32BytesLE(bi)));
            return acc;
        }, [] as number[]);
        return new Uint8Array(flattened);
    }

    static toSolanaCalldata(proof: any, publicSignals: any): Uint8Array {
        const { unstringifyBigInts } = utils;
        const p = unstringifyBigInts(proof);
        const inputs = unstringifyBigInts(publicSignals);

        const proofA = ZkSolana.packG1(p.pi_a);
        const proofB = ZkSolana.packG2(p.pi_b);
        const proofC = ZkSolana.packG1(p.pi_c);
        const pubInputs = ZkSolana.packPublicInputs(inputs);

        return new Uint8Array([
            ...proofA,
            ...proofB,
            ...proofC,
            ...pubInputs
        ]);
    }

    static toSolanaCalldataBuffer(proof: any, publicSignals: any): Buffer[] {
        const { unstringifyBigInts } = utils;
        const p = unstringifyBigInts(proof);
        const inputs = unstringifyBigInts(publicSignals);

        const proofA = ZkSolana.packG1(p.pi_a);      // Uint8Array
        const proofB = ZkSolana.packG2(p.pi_b);      // Uint8Array
        const proofC = ZkSolana.packG1(p.pi_c);      // Uint8Array
        const pubInputs = ZkSolana.packPublicInputs(inputs); // Uint8Array

        const flatCalldata = new Uint8Array([
            ...proofA,
            ...proofB,
            ...proofC,
            ...pubInputs
        ]);

        // Check it's a multiple of 32
        if (flatCalldata.length % 32 !== 0) {
            throw new Error(`Calldata length ${flatCalldata.length} is not divisible by 32`);
        }

        // Split into Vec<[u8; 32]>
        const chunks: Buffer[] = [];
        for (let i = 0; i < flatCalldata.length; i += 32) {
            const chunk = flatCalldata.slice(i, i + 32);
            chunks.push(Buffer.from(chunk)); // Convert Uint8Array -> Buffer
        }

        return chunks;
    }

    static parsePublicInputsFromBuffer(
        inputBuffer: Uint8Array,
        numPublicInputs: number
    ): ParsedProofInputs {
        const PUBLIC_INPUT_OFFSET = 256;
        const inputSize = 32;
        const publicInputs: Uint8Array[] = [];

        for (let i = 0; i < numPublicInputs; i++) {
            const start = PUBLIC_INPUT_OFFSET + i * inputSize;
            const end = start + inputSize;
            publicInputs.push(inputBuffer.slice(start, end));
        }

        if (publicInputs.length < 4) {
            throw new Error("Expected at least 4 public inputs");
        }

        // Parse nullifierHash as bigint (little-endian)
        const nullifierHash = publicInputs[0].reduce(
            (acc, byte, i) => acc + (BigInt(byte) << BigInt(8 * i)),
            BigInt(0)
        );

        // Parse mintPubkey from 32 bytes into base58
        const mintPubkey = new PublicKey(publicInputs[1]).toBase58();

        // Parse amount (first 8 bytes as LE)
        const amountBytes = publicInputs[2].slice(0, 8);
        const amount = amountBytes.reduce(
            (acc, byte, i) => acc + (BigInt(byte) << BigInt(8 * i)),
            BigInt(0)
        );

        // Parse mode from first byte of 4th input
        const mode = publicInputs[3][0];

        return {
            publicInputs,
            nullifierHash,
            mintPubkey,
            amount,
            mode,
        };
    }
}