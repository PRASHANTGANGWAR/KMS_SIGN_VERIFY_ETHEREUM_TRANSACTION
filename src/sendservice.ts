

import { Web3Service } from './Web3Service';
const web3Service = new Web3Service();
import { contractAddress } from './config/config';


// parameter to be configured
const arrAddress = ["0xcbda620420fca788dd0ed4d3ce108ea782a3f457", "0xba710efe2546c72f8ea853794fa91dcd9150362c"];
const arrAmt = [20000000, 3000000];

export const rawTransactionBulk = async (senderAddress) => {
  try {
    let rawData = await web3Service.getDataForBulkTransfer(arrAddress, arrAmt)
    if (!rawData) {
      return { success: false, message: 'Unable to fetch data to sign' }
    }
    let gasPrice = await web3Service.getGasPrice();
    let nonce = await web3Service.getNonce(senderAddress)
    //from, to, data, value
    let estimatedGas = await web3Service.estimateGas({ from: senderAddress, to: contractAddress, data: rawData, value: 0, nonce: nonce })
    if (!estimatedGas) {
      return { success: false, message: 'This transaction is likely to fail on blockchain' }
    }

    let data = { data: rawData, value: 0, gas: estimatedGas, gasPrice: gasPrice, nonce }
    console.log("---------------------------", data)

    return { success: true, data: data }
  } catch (e) {
    return { success: false, message: e.message }
  }
}
