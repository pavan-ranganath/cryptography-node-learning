// Import necessary modules from node-seal
import SEAL from "node-seal";
import { CipherText } from "node-seal/implementation/cipher-text";
import { PlainText } from "node-seal/implementation/plain-text";
import { SEALLibrary } from "node-seal/implementation/seal";
import { ComprModeType } from "node-seal/implementation/compr-mode-type";
import * as readlineSync from "readline-sync"; // Import readline-sync module

// Define input values
const CONSOLE_PRINT_ENCRYPTED_STRING = false;

// Function to take inputs from the user
function getUserInputs() {
  // Get user input for INPUT1
  const INPUT1 = readlineSync.questionInt("Enter the first input: ");

  // Get user input for INPUT2
  const INPUT2 = readlineSync.questionInt("Enter the second input: ");

  return { INPUT1, INPUT2 };
}
// Function to get the homomorphic operation choice from the user
function getHomomorphicOperation() {
  const operations = ["add", "sub", "multiply"];
  const index = readlineSync.keyInSelect(
    operations,
    "Choose a homomorphic operation:"
  );
  if (index === -1) {
    console.log("Operation selection canceled. Exiting.");
    process.exit(0);
  }
  return operations[index];
}
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

// Main function for homomorphic encryption
async function performHomomorphicEncryption(
  INPUT1: number,
  INPUT2: number,
  operation: string
) {
  // Initialize SEAL library
  const seal = await SEAL();

  // Set up homomorphic encryption
  const { context, encoder, evaluator, encryptor, decryptor } =
    setupHomomorphicEncryption(seal);

  // Define input arrays
  const array1 = Int32Array.from([INPUT1]);
  const array2 = Int32Array.from([INPUT2]);

  // Encode plaintexts
  const plainText1 = encoder.encode(array1) as PlainText;
  const plainText2 = encoder.encode(array2) as PlainText;

  // Print plaintexts
  console.log("Plaintext 1:", array1);
  console.log("Plaintext 2:", array2);

  // Encrypt plaintexts
  const cipherText1 = encryptor.encrypt(plainText1) as CipherText;
  const cipherText2 = encryptor.encrypt(plainText2) as CipherText;

  // Perform the selected homomorphic operation
  let result;
  switch (operation) {
    case "add":
      result = evaluator.add(cipherText1, cipherText2);
      break;
    case "sub":
      result = evaluator.sub(cipherText1, cipherText2);
      break;
    case "multiply":
      result = evaluator.multiply(cipherText1, cipherText2);
      break;
    default:
      console.error("Invalid operation choice.");
      return;
  }

  if (!result) {
    return;
  }

  CONSOLE_PRINT_ENCRYPTED_STRING
    ? console.log(
        `Encrypted (Homomorphic ${operation}):`,
        result.save(
          getComprModeType("zlib", { ComprModeType: seal.ComprModeType })
        )
      )
    : "";

  // Decrypt and print the result
  const decryptedPlainText = decryptor.decrypt(result) as PlainText;
  const decodedArray = encoder.decode(decryptedPlainText);
  console.log(`Decrypted (Homomorphic ${operation}): `, decodedArray[0]);
}
// Main asynchronous function
// Main asynchronous function
async function main() {
  while (true) {
    // Get user inputs
    const { INPUT1, INPUT2 } = getUserInputs();

    // Get homomorphic operation choice from the user
    const operation = getHomomorphicOperation();

    // Perform homomorphic encryption with user inputs
    await performHomomorphicEncryption(INPUT1, INPUT2, operation);

    // Ask the user if they want to continue
    const continueChoice = readlineSync.keyInYNStrict("Do you want to continue?");
    if (!continueChoice) {
      console.log("Exiting program. Goodbye!");
      break;
    }
  }
}

// Run the main asynchronous function
main().catch((error) => console.error(error));