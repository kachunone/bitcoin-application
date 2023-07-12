from hashlib import sha256
import datetime
import Crypto
import Crypto.Random
from Crypto.PublicKey import RSA
from Crypto.Signature import PKCS1_v1_5
from Crypto.Hash import SHA
import binascii
import json
import requests
from flask import Flask, jsonify, request
from urllib.parse import urlparse
import time

app = Flask(__name__)


class Transaction:
    def __init__(self, sender, recipient, value, signature, id, fee):
        self.sender = sender
        self.recipient = recipient
        self.value = value
        self.signature = signature
        self.id = id
        self.fee = fee

    def to_dict(self):
        return ({
            'sender': self.sender,
            'recipient': self.recipient,
            'value': self.value})

    def add_signature(self, signature):
        self.signature = signature

    def verify_transaction_signature(self):
        if hasattr(self, 'signature'):
            public_key = RSA.importKey(binascii.unhexlify(self.sender))
            verifier = PKCS1_v1_5.new(public_key)
            h = SHA.new(str(self.to_dict()).encode('utf8'))
            return verifier.verify(h, binascii.unhexlify(self.signature))
        else:
            return False

    def to_json(self):
        return json.dumps(self.__dict__, sort_keys=False)


class Wallet:
    def __init__(self):
        random = Crypto.Random.new().read
        self._private_key = RSA.generate(1024, random)
        self._public_key = self._private_key.publickey()
        self.balance = 0

    def sign_transaction(self, transaction: Transaction):
        signer = PKCS1_v1_5.new(self._private_key)
        h = SHA.new(str(transaction.to_dict()).encode('utf8'))
        return binascii.hexlify(signer.sign(h)).decode('ascii')

    @property
    def identity(self):
        pubkey = binascii.hexlify(self._public_key.exportKey(format='DER'))
        return pubkey.decode('ascii')

    @property
    def identity_private(self):
        prikey = binascii.hexlify(self._private_key.exportKey(format='DER'))
        return prikey.decode('ascii')


class Block:
    def __init__(self, index, transactions, timestamp, previous_hash, hash, nonce, difficulty):
        self.index = index
        self.transactions = transactions
        self.timestamp = timestamp
        self.previous_hash = previous_hash
        self.hash = hash
        self.nonce = nonce
        self.difficulty = difficulty

    def to_dict(self):
        return ({
            'index': self.index,
            'transactions': self.transactions,
            'timestamp': self.timestamp,
            'previous_hash': self.previous_hash,
            'nonce': self.nonce}
        )

    def to_json(self):
        return json.dumps(self.__dict__)

    def compute_hash(self):
        return sha256(str(self.to_dict()).encode()).hexdigest()


class Blockchain:

    def __init__(self):
        self.unconfirmed_transactions = []
        self.chain = []
        self.create_genesis_block()
        self.nodes = set()
        self.difficulty = 2

    def create_genesis_block(self):
        block_reward = Transaction("Block_Reward", myWallet.identity, "5.0", None, None, None).to_json()
        genesis_block = Block(0, block_reward, datetime.datetime.now().strftime("%m/%d/%Y, %H:%M:%S"), "0", None, None, None)
        genesis_block.hash = genesis_block.compute_hash()
        self.chain.append(genesis_block.to_json())

    def add_new_transaction(self, transaction: Transaction):
        if transaction.verify_transaction_signature() and blockchain.check_balance(transaction):
            self.unconfirmed_transactions.append(transaction.to_json())
            blockchain.broadcast_transaction(transaction)
            return True
        else:
            return False

    def add_block(self, block, proof):
        previous_hash = self.last_block['hash']
        if previous_hash != block.previous_hash:
            return False
        if not self.is_valid_proof(block, proof) and self.difficulty == block.difficulty:
            return False
        block.hash = proof
        self.chain.append(block.to_json())
        return True

    def is_valid_proof(self, block, block_hash):
        return (block_hash.startswith('0' * block.difficulty) and
                block_hash == block.compute_hash())

    def proof_of_work(self, block):
        block.nonce = 0

        computed_hash = block.compute_hash()
        while not computed_hash.startswith('0' * self.difficulty):
            block.nonce += 1
            computed_hash = block.compute_hash()
        return computed_hash

    def mine(self, myWallet):

        reward = 5
        for t in self.unconfirmed_transactions:
            t = json.loads(t)
            reward += float(t['fee'])

        block_reward = Transaction("Block_Reward", myWallet.identity, str(reward), None, None, None).to_json()
        self.unconfirmed_transactions.insert(0, block_reward)
        if not self.unconfirmed_transactions:
            return False
        new_block = Block(index=self.last_block['index'] + 1,
                          transactions=self.unconfirmed_transactions,
                          timestamp=datetime.datetime.now().strftime("%m/%d/%Y, %H:%M:%S"),
                          previous_hash=self.last_block['hash'],
                          hash=None,
                          nonce=0,
                          difficulty=self.difficulty)
        proof = self.proof_of_work(new_block)
        if self.add_block(new_block, proof):
            index = int(self.last_block['index'])
            if int(index / 3)* 3 == index:  ###############################
                blockchain.adjust_difficulty()  ###############################
            self.unconfirmed_transactions = []
            return new_block
        else:
            return False

    def register_node(self, node_url):
        # Checking node_url has valid format
        parsed_url = urlparse(node_url)
        if parsed_url.netloc:
            self.nodes.add(parsed_url.netloc)
        elif parsed_url.path:
            # Accepts an URL without scheme like '192.168.0.5:5000'.
            self.nodes.add(parsed_url.path)
        else:
            raise ValueError('Invalid URL')

    def consensus(self):
        neighbours = self.nodes
        new_chain = None
        # We're only looking for chains longer than ours
        max_length = len(self.chain)
        # Grab and verify the chains from all the nodes in our network
        for node in neighbours:
            response = requests.get('http://' + node + '/fullchain')
            if response.status_code == 200:
                length = response.json()['length']
                chain = response.json()['chain']
                # Check if the length is longer and the chain is valid
                if length > max_length and self.valid_chain(chain):
                    max_length = length
                    new_chain = chain
                    new_difficulty = response.json()['current_difficulty']
        # Replace our chain if longer chain is found
        if new_chain:
            self.chain = json.loads(new_chain)
            self.difficulty = int(new_difficulty)
            return True
        return False

    def valid_chain(self, chain):
        # check if a blockchain is valid
        current_index = 0
        chain = json.loads(chain)
        while current_index < len(chain):
            block = json.loads(chain[current_index])
            current_block = Block(block['index'],
                                  block['transactions'],
                                  block['timestamp'],
                                  block['previous_hash'],
                                  block['hash'],
                                  block['nonce'],
                                  block['difficulty'])
            if current_index + 1 < len(chain):
                if current_block.compute_hash() != json.loads(chain[current_index + 1])['previous_hash']:
                    return False
            if isinstance(current_block.transactions, list):
                for transaction in current_block.transactions:
                    transaction = json.loads(transaction)
                    # skip Block reward because it does not have signature
                    if transaction['sender'] == 'Block_Reward':
                        continue
                    current_transaction = Transaction(transaction['sender'],
                                                      transaction['recipient'],
                                                      transaction['value'],
                                                      transaction['signature'],
                                                      transaction['id'],
                                                      transaction['fee'])
                    # validate digital signature of each transaction
                    if not current_transaction.verify_transaction_signature():
                        return False
                if not self.is_valid_proof(current_block, block['hash']):
                    return False
            current_index += 1
        return True

    ############################################################################
    def get_balance_whole(self, client):
        current_index = 0
        sum_input = 0
        sum_output = 0
        while current_index < len(self.chain):
            block = json.loads(self.chain[current_index])
            trans_list = block['transactions']
            if isinstance(trans_list, list):
                for trans in trans_list:
                    trans = json.loads(trans)
                    if client == trans['sender']:
                        sum_output += float(trans['value']) + float(trans['fee'])
                    if client == trans['recipient']:
                        sum_input += float(trans['value'])
            else:
                trans = json.loads(trans_list)
                if client == trans['sender']:
                    sum_output += float(trans['value']) + float(trans['fee'])
                if client == trans['recipient']:
                    sum_input += float(trans['value'])
            current_index += 1
        return sum_input - sum_output

    def check_balance(self, transaction: Transaction):
        balance = self.get_balance_whole(transaction.sender)
        cost = float(transaction.value) + float(transaction.fee)
        for t in self.unconfirmed_transactions:
            t = json.loads(t)
            if t['id'] != transaction.id and t['sender'] == transaction.sender:
                cost += float(t['value']) + float(t['fee'])
        if balance >= cost:
            return True
        else:
            return False

    def broadcast_transaction(self, transaction: Transaction):
        neighbours = self.nodes
        info = {'sender': transaction.sender,
                'recipient': transaction.recipient,
                'value': transaction.value,
                'signature': transaction.signature,
                'id': transaction.id,
                'fee': transaction.fee}
        for n in neighbours:
            requests.post('http://' + n + '/receive_transaction', data=info)

    def remove_comfirmed_transactions(self):
        trans_in_block = self.last_block['transactions']

        if isinstance(trans_in_block, list):
            for i in range(len(trans_in_block)):
                txid_block = json.loads(trans_in_block[i])
                for j in range(len(self.unconfirmed_transactions)):
                    txid_pool = json.loads(self.unconfirmed_transactions[j])
                    if txid_block['id'] == txid_pool['id']:
                        del self.unconfirmed_transactions[j]
                        break
        else:
            trans_in_block = json.loads(trans_in_block)
            for i in range(len(self.unconfirmed_transactions)):
                txid_pool = json.loads(self.unconfirmed_transactions[i])['id']
                if txid_pool['id'] == trans_in_block['id']:
                    del self.unconfirmed_transactions[i]
                    break

    def adjust_difficulty(self):
        last_block_time = self.last_block['timestamp']
        third_last_time = json.loads(self.chain[-3])['timestamp']
        a = time.strptime(last_block_time, "%m/%d/%Y, %H:%M:%S")
        b = time.strptime(third_last_time, "%m/%d/%Y, %H:%M:%S")
        t1 = datetime.datetime(a.tm_year, a.tm_mon, a.tm_mday, a.tm_hour, a.tm_min, a.tm_sec)
        t2 = datetime.datetime(b.tm_year, b.tm_mon, b.tm_mday, b.tm_hour, b.tm_min, b.tm_sec)

        if (t1 - t2).seconds / 3 > 10:
            if self.difficulty > 1:
                self.difficulty -= 1
        elif (t1 - t2).seconds / 3 < 10:
            if self.difficulty < 6:
                self.difficulty += 1

    ############################################################################

    @property
    def last_block(self):
        return json.loads(self.chain[-1])


@app.route('/new_transaction', methods=['POST'])
def new_transaction():
    values = request.form
    required = ['recipient_address', 'amount', 'fee']
    # Check that the required fields are in the POST data
    if not all(k in values for k in required):
        return 'Missing values', 400

    txid = str(myWallet.identity
               + values['recipient_address']
               + values['amount']
               + datetime.datetime.now().strftime("%m/%d/%Y, %H:%M:%S"))
    txid = sha256(txid.encode()).hexdigest()

    transaction = Transaction(myWallet.identity, values['recipient_address'], values['amount'],
                              None, txid, values['fee'])

    transaction.add_signature(myWallet.sign_transaction(transaction))
    transaction_result = blockchain.add_new_transaction(transaction)

    if transaction_result:
        response = {'message': 'Transaction will be added to Block '}
        return jsonify(response), 201
    else:
        response = {'message': 'Invalid Transaction!'}
        return jsonify(response), 406


@app.route('/get_transactions', methods=['GET'])
def get_transactions():
    # Get transactions from transactions pool
    transactions = blockchain.unconfirmed_transactions
    response = {'transactions': transactions}
    return jsonify(response), 200


@app.route('/chain', methods=['GET'])
def part_chain():
    response = {
        'chain': blockchain.chain[-10:],
        'length': len(blockchain.chain),
    }
    return jsonify(response), 200


@app.route('/fullchain', methods=['GET'])
def full_chain():
    myWallet.balance = blockchain.get_balance_whole(myWallet.identity)
    response = {
        'chain': json.dumps(blockchain.chain),
        'length': len(blockchain.chain),
        'current_difficulty': blockchain.difficulty,
        'balance_of_this_client': myWallet.balance,
    }
    return jsonify(response), 200


@app.route('/get_nodes', methods=['GET'])
def get_nodes():
    nodes = list(blockchain.nodes)
    response = {'nodes': nodes}
    return jsonify(response), 200


@app.route('/register_node', methods=['POST'])
def register_node():
    values = request.form
    node = values.get('node')
    com_port = values.get('com_port')
    # handle type B request
    if com_port is not None:
        blockchain.register_node(request.remote_addr + ":" + com_port)
        return "ok", 200
    # handle type A request
    if node is None and com_port is None:
        return "Error: Please supply a valid nodes", 400
    blockchain.register_node(node)
    # retrieve nodes list
    node_list = requests.get('http://' + node + '/get_nodes')
    if node_list.status_code == 200:
        node_list = node_list.json()['nodes']
        for node in node_list:
            blockchain.register_node(node)
    for new_nodes in blockchain.nodes:
        # sending type B request
        requests.post('http://' + new_nodes + '/register_node', data={'com_port': str(port)})
        # check if our chain is authoritative from other nodes
        replaced = blockchain.consensus()
    if replaced:
        response = {
            'message': 'Longer authoritative chain found from peers, replacing ours',
            'total_nodes': [node for node in blockchain.nodes]
        }
    else:
        response = {
            'message': 'New nodes have been added, but our chain is authoritative',
            'total_nodes': [node for node in blockchain.nodes]
        }
    return jsonify(response), 201


@app.route('/consensus', methods=['GET'])
def consensus():
    replaced = blockchain.consensus()
    if replaced:
        blockchain.remove_comfirmed_transactions()  ###############################
        response = {'message': 'Our chain was replaced', }
    else:
        response = {'message': 'Our chain is authoritative', }
    return jsonify(response), 200


@app.route('/mine', methods=['GET'])
def mine():
    newblock = blockchain.mine(myWallet)
    for node in blockchain.nodes:
        requests.get('http://' + node + '/consensus')
    response = {
        'index': newblock.index,
        'transactions': newblock.transactions,
        'timestamp': newblock.timestamp,
        'nonce': newblock.nonce,
        'hash': newblock.hash,
        'previous_hash': newblock.previous_hash
    }
    return jsonify(response), 200


@app.route('/receive_transaction', methods=['POST'])
def receive_transaction():
    data = request.form
    new_trans = Transaction(data.get('sender'), data.get('recipient'),
                            data.get('value'), data.get('signature'),
                            data.get('id'), data.get('fee'))
    blockchain.check_balance(new_trans)
    blockchain.unconfirmed_transactions.append(new_trans.to_json())
    response = {'message': 'trans is accepted', }
    return jsonify(response), 201


if __name__ == '__main__':
    myWallet = Wallet()
    blockchain = Blockchain()
    port = 5000
    app.run(host='127.0.0.1', port=port)
