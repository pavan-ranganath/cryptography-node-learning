// Import necessary modules from node-seal
import SEAL from "node-seal";
import { CipherText } from "node-seal/implementation/cipher-text";
import { PlainText } from "node-seal/implementation/plain-text";
import { SEALLibrary } from "node-seal/implementation/seal";
import { ComprModeType } from "node-seal/implementation/compr-mode-type";
// Define input values
const INPUT1 = 50;
const INPUT2 = 100;
const CONSOLE_PRINT_ENCRYPTED_STRING = true;

function getComprModeType(
  compression: "none" | "zlib" | "zstd",
  { ComprModeType }: { ComprModeType: ComprModeType }
) {
  switch (compression) {
    case "none":
      return ComprModeType.none;

    case "zlib":
      return ComprModeType.zlib;

    case "zstd":
      return ComprModeType.zstd;

    default:
      return ComprModeType.zstd;
  }
}

// Function to set up homomorphic encryption
function setupHomomorphicEncryption(seal: SEALLibrary) {
  console.log("Setting up homomorphic encryption...");

  // Define encryption parameters
  const schemeType = seal.SchemeType.bfv;
  const securityLevel = seal.SecurityLevel.tc128;
  const polyModulusDegree = 4096;
  const bitSizes = [36, 36, 37];
  const bitSize = 20;

  // Create EncryptionParameters
  const encParms = seal.EncryptionParameters(schemeType);

  // Set the PolyModulusDegree
  encParms.setPolyModulusDegree(polyModulusDegree);

  // Create a suitable set of CoeffModulus primes
  encParms.setCoeffModulus(
    seal.CoeffModulus.Create(polyModulusDegree, Int32Array.from(bitSizes))
  );

  // Set the PlainModulus to a prime of bitSize 20.
  encParms.setPlainModulus(
    seal.PlainModulus.Batching(polyModulusDegree, bitSize)
  );

  // Create a new Context
  const context = seal.Context(
    encParms, // Encryption Parameters
    true, // ExpandModChain
    securityLevel // Enforce a security level
  );

  if (!context.parametersSet()) {
    throw new Error(
      "Could not set the parameters in the given context. Please try different encryption parameters."
    );
  }

  // Initialize keys and other necessary components
  const keyGenerator = seal.KeyGenerator(context);
  const secretKey = keyGenerator.secretKey();
  const publicKey = keyGenerator.createPublicKey();

  const encoder = seal.BatchEncoder(context);
  const evaluator = seal.Evaluator(context);

  const encryptor = seal.Encryptor(context, publicKey);
  const decryptor = seal.Decryptor(context, secretKey);

  return { context, encoder, evaluator, encryptor, decryptor };
}

// Main asynchronous function
(async () => {
  // Initialize SEAL library
  const seal = await SEAL();

  // Set up homomorphic encryption
  const { context, encoder, evaluator, encryptor, decryptor } =
    setupHomomorphicEncryption(seal);

  // Define input arrays
  var in1 = [INPUT1];
  var in2 = [INPUT2];

  const array1 = Int32Array.from(in1);
  const array2 = Int32Array.from(in2);

  // Encode plaintexts
  const plainText1 = encoder.encode(array1) as PlainText;
  const plainText2 = encoder.encode(array2) as PlainText;

  // Print plaintexts
  console.log("Plaintext 1:", array1);
  console.log("Plaintext 2:", array2);

  // Encrypt plaintexts
  var cipherText1 = encryptor.encrypt(plainText1) as CipherText;
  var cipherText2 = encryptor.encrypt(plainText2) as CipherText;

  // Homomorphic addition
  var homographicEncryptedSum = evaluator.add(cipherText1, cipherText2);
  if (!homographicEncryptedSum) {
    return;
  }
  CONSOLE_PRINT_ENCRYPTED_STRING
    ? console.log(
        "Encrypted (Homomorphic Add):",
        homographicEncryptedSum.save(
          getComprModeType("zlib", { ComprModeType: seal.ComprModeType })
        )
      )
    : "";

  // Decrypt and print result of addition
  var decryptedSumPlainText = decryptor.decrypt(
    homographicEncryptedSum
  ) as PlainText;
  var decodedSumArray = encoder.decode(decryptedSumPlainText);
  console.log("Decrypted (Homomorphic Add): ", decodedSumArray[0]);

  // Homomorphic subtraction
  var homographicEncryptedSub = evaluator.sub(cipherText1, cipherText2);
  if (!homographicEncryptedSub) {
    return;
  }
  CONSOLE_PRINT_ENCRYPTED_STRING
    ? console.log(
        "Encrypted (Homomorphic Subtraction):",
        homographicEncryptedSub.save(
          getComprModeType("zlib", { ComprModeType: seal.ComprModeType })
        )
      )
    : "";

  // Decrypt and print result of subtraction
  var decryptedSubPlainText = decryptor.decrypt(
    homographicEncryptedSub
  ) as PlainText;
  var decodedSubArray = encoder.decode(decryptedSubPlainText);
  console.log("Decrypted (Homomorphic Subtraction): ", decodedSubArray[0]);

  // Homomorphic multiplication
  var homographicEncryptedMultiply = evaluator.multiply(
    cipherText1,
    cipherText2
  );
  if (!homographicEncryptedMultiply) {
    return;
  }
  CONSOLE_PRINT_ENCRYPTED_STRING
    ? console.log(
        "Encrypted (Homomorphic Multiply):",
        homographicEncryptedMultiply.save(
          getComprModeType("zlib", { ComprModeType: seal.ComprModeType })
        )
      )
    : "";

  // Decrypt and print result of multiplication
  var decryptedMultiplyPlainText = decryptor.decrypt(
    homographicEncryptedMultiply
  ) as PlainText;
  var decodedMultiplyArray = encoder.decode(decryptedMultiplyPlainText);
  console.log("Decrypted (Homomorphic Multiply): ", decodedMultiplyArray[0]);
})();
