import Web3 from 'web3';
import { abi, contractAddress, max_limit } from './config/config';

/** Web3 service to interact with ethereum API's */
export class Web3Service {
    readonly web3: Web3;
    readonly oTokenContract: any;
    readonly rpcAddress: any = "https://ropsten.infura.io/v3/4c6accf3e0964ae78bb9ad1575d2bf48";
    
    constructor() {
        const rpcAddress = this.rpcAddress
        const contractAddress = '0x1600fa4de5b629c767b9e9defdb57df13d6ffb9d'

        this.web3 = new Web3();
        const web3Provider = new Web3.providers.HttpProvider(rpcAddress);
        this.web3.setProvider(web3Provider);
        this.oTokenContract = new this.web3.eth.Contract(abi, contractAddress);
    }

    /**
     * Get balance for an address from OT contract
     * @param {string} address account/smart contract address
     * @returns {Promise<number>}
     */
    public balanceOf(address: string): Promise<number> {
        return this.oTokenContract.methods.balanceOf(address).call();
    }

    public getGasPrice = async () => {
        return this.web3.eth.getGasPrice();
    }

    public getNonce = async (address) => {
        return this.web3.eth.getTransactionCount(address, 'pending')
    }

    public estimateGas = async (payload) => {
        let { from, to, data, value, nonce } = payload
        let estimatedGas = await this.web3.eth.estimateGas({ from, to, value, data, nonce })
        if (estimatedGas >= max_limit) {
            return null;
        } else {
            return estimatedGas;
        }
    }

    public getDataForBulkTransfer = async (arrAddress, arrAmt) => {
          if (!arrAddress || !arrAmt) {
            return null;
          }
          let extraData = this.oTokenContract.methods.bulkTransfer(arrAddress, arrAmt, true);
          return extraData.encodeABI()
      }
}
