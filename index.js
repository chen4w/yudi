var lisk = require('lisk-js');
var crypto = require('crypto');

var util = require('util');
var ByteBuffer = require('bytebuffer');
var bignum = require('browserify-bignum');

var nacl_factory = require('js-nacl');
var nacl = nacl_factory.instantiate();
var fs = require('fs');



function getBytes(block) {
	var size = 4 + 4 + 8 + 4 + 4 + 8 + 8 + 4 + 4 + 4 + 32 + 32 + 64;

	var bb = new ByteBuffer(size, true);
	bb.writeInt(block.version);
	bb.writeInt(block.timestamp);

	if (block.previousBlock) {
		var pb = bignum(block.previousBlock).toBuffer({size: '8'});

		for (var i = 0; i < 8; i++) {
			bb.writeByte(pb[i]);
		}
	} else {
		for (var i = 0; i < 8; i++) {
			bb.writeByte(0);
		}
	}

	bb.writeInt(block.numberOfTransactions);
	bb.writeLong(block.totalAmount);
	bb.writeLong(block.totalFee);

	bb.writeInt(block.payloadLength);

	var payloadHashBuffer = new Buffer(block.payloadHash, 'hex');
	for (var i = 0; i < payloadHashBuffer.length; i++) {
		bb.writeByte(payloadHashBuffer[i]);
	}

	var generatorPublicKeyBuffer = new Buffer(block.generatorPublicKey, 'hex');
	for (var i = 0; i < generatorPublicKeyBuffer.length; i++) {
		bb.writeByte(generatorPublicKeyBuffer[i]);
	}

	if (block.blockSignature) {
		var blockSignatureBuffer = new Buffer(block.blockSignature, 'hex');
		for (var i = 0; i < blockSignatureBuffer.length; i++) {
			bb.writeByte(blockSignatureBuffer[i]);
		}
	}

	bb.flip();
	var b = bb.toBuffer();

	return b;
}


var bytesTypes = {
	2: function (trs) {
		try {
			var buf = new Buffer(trs.asset.delegate.username, 'utf8');
		} catch (e) {
			throw Error(e.toString());
		}

		return buf;
	},

	3: function (trs) {
		try {
			var buf = trs.asset.votes ? new Buffer(trs.asset.votes.join(''), 'utf8') : null;
		} catch (e) {
			throw Error(e.toString());
		}

		return buf;
	},

	5: function (trs) {
		try {
			var buf = new Buffer([]);
			var nameBuf = new Buffer(trs.asset.dapp.name, 'utf8');
			buf = Buffer.concat([buf, nameBuf]);

			if (trs.asset.dapp.description) {
				var descriptionBuf = new Buffer(trs.asset.dapp.description, 'utf8');
				buf = Buffer.concat([buf, descriptionBuf]);
			}

			if (trs.asset.dapp.git) {
				buf = Buffer.concat([buf, new Buffer(trs.asset.dapp.git, 'utf8')]);
			}

			var bb = new ByteBuffer(4 + 4, true);
			bb.writeInt(trs.asset.dapp.type);
			bb.writeInt(trs.asset.dapp.category);
			bb.flip();

			buf = Buffer.concat([buf, bb.toBuffer()]);
		} catch (e) {
			throw Error(e.toString());
		}

		return buf;
	}
}

function getTransactionBytes(trs, skipSignature) {
	var assetBytes, assetSize;

	if (trs.type > 0) {
		assetBytes = bytesTypes[trs.type](trs);
		assetSize = assetBytes ? assetBytes.length : 0;
	} else {
		assetSize = 0;
	}

	var bb = new ByteBuffer(1 + 4 + 32 + 32 + 8 + 8 + 64 + 64 + assetSize, true);
	bb.writeByte(trs.type);
	bb.writeInt(trs.timestamp);

	var senderPublicKeyBuffer = new Buffer(trs.senderPublicKey, 'hex');
	for (var i = 0; i < senderPublicKeyBuffer.length; i++) {
		bb.writeByte(senderPublicKeyBuffer[i]);
	}

	if (trs.recipientId) {
		var recipient = trs.recipientId.slice(0, -1);
		recipient = bignum(recipient).toBuffer({size: 8});

		for (var i = 0; i < 8; i++) {
			bb.writeByte(recipient[i] || 0);
		}
	} else {
		for (var i = 0; i < 8; i++) {
			bb.writeByte(0);
		}
	}

	bb.writeLong(trs.amount);

	if (assetSize > 0) {
		for (var i = 0; i < assetSize; i++) {
			bb.writeByte(assetBytes[i]);
		}
	}

	if (!skipSignature && trs.signature) {
		var signatureBuffer = new Buffer(trs.signature, 'hex');
		for (var i = 0; i < signatureBuffer.length; i++) {
			bb.writeByte(signatureBuffer[i]);
		}
	}

	bb.flip();

	return bb.toBuffer();
}

 function sign(keypair, data) {
	var hash = crypto.createHash('sha256').update(data).digest();
	var signature = nacl.crypto_sign_detached(hash, new Buffer(keypair.privateKey, 'hex'));
	return new Buffer(signature).toString('hex');
}

function getId(data) {
	var hash = crypto.createHash('sha256').update(data).digest();
	var temp = new Buffer(8);
	for (var i = 0; i < 8; i++) {
		temp[i] = hash[7 - i];
	}

	var id = bignum.fromBuffer(temp).toString();
	return id;
}

var map_keys = {};
var map_addrs ={};
var map_passphrases ={};
var transactions=[];
var totalAmount="10000000000000000";

var master_id ='master';
var passphrase = '';

var passphrase = "passphrase.master";
var key_pair = lisk.crypto.getKeys(passphrase);
map_passphrases[master_id]=passphrase;
map_keys[master_id]=key_pair;
map_addrs[master_id]=lisk.crypto.getAddress(key_pair.publicKey);



//加快debug速度,101用2
var delegate_cout=2;
var votes=[];
//生成101个代表的密钥对和地址
for(var i=0; i<delegate_cout; i++){
    var delegate_id = 'delegate_'+i;
    var passphrase="passphrase.delegate_"+i;
    map_passphrases[voter_id]=passphrase;

    key_pair=lisk.crypto.getKeys(passphrase);
    map_keys[delegate_id]=key_pair;
    var addr =lisk.crypto.getAddress(key_pair.publicKey);
    map_addrs[delegate_id]=addr;
    //101个委托人生成交易（自己注册成type2）；
    //var transaction = lisk.delegate.createDelegate(passphrase, "genesis_"+i);
    //弃用lisk-js api, 自行组织transaction
    var transaction = {
        type: 2,
        amount: 0,
        fee: 0,
        timestamp: 0,
        recipientId: null,
        senderId: addr,
        senderPublicKey: key_pair.publicKey,
        asset: {
            delegate: {
                username: "genesis_"+i
            }
        }
    }

    bytes = getTransactionBytes(transaction);
    transaction.signature = sign(map_keys[master_id], bytes);
    bytes = getTransactionBytes(transaction);
    transaction.id = getId(bytes);
    
    transactions.push(transaction);
    //投票人给101各委托人的投票交易（交易类型type3）；
    //var voter_id = 'voter_'+i;
     //弃用lisk-js api, 自行组织transaction
     votes.push("+" + key_pair.publicKey);
    //transaction = lisk.vote.createVote(map_passphrases[voter_id], ["+"+key_pair.publicKey]);

    //transactions.push(transaction);
}
 //弃用lisk-js api, 自行组织vote transaction
var voter_cout=2;
//生成投票人的密钥对和地址
for(var i=0; i<voter_cout; i++){
    var voter_id = 'voter_'+i;
    var passphrase="passphrase.voter_"+i;
    map_passphrases[voter_id]=passphrase;
    key_pair=lisk.crypto.getKeys(passphrase);
    map_keys[voter_id]=key_pair;
    var addr =lisk.crypto.getAddress(key_pair.publicKey);
    map_addrs[voter_id]=addr;
}

//生成投票交易
var voteTransaction = {
    type: 3,
    amount: 0,
    fee: 0,
    timestamp: 0,
    recipientId: map_addrs[master_id],
    senderId: map_addrs[master_id],
    senderPublicKey: map_keys[master_id].publicKey,
    asset: {
        votes: votes
    }
}
bytes = getTransactionBytes(voteTransaction);
voteTransaction.signature = sign(map_keys[master_id], bytes);
bytes = getTransactionBytes(voteTransaction);
voteTransaction.id = getId(bytes);
transactions.push(voteTransaction);    

//产生第一个交易，为第一个投票人写入初始的余额
var totalAmount      = 1000 * Math.pow(10, 8); // 100000000000
//var transaction = lisk.transaction.createTransaction(map_addrs['voter_0'], totalAmount, map_passphrases[master_id]);
var balanceTransaction = {
    type: 0,
    amount: totalAmount,
    fee: 0,
    timestamp: 0,
    recipientId: map_addrs['voter_0'],
    senderId: map_addrs[master_id],
    senderPublicKey: map_keys[master_id].publicKey
};
var bytes = getTransactionBytes(balanceTransaction);
balanceTransaction.signature = sign(map_keys[master_id], bytes);
bytes = getTransactionBytes(balanceTransaction);
balanceTransaction.id = getId(bytes);

transactions.push(balanceTransaction);

 
//构造block,借鉴cli\helpers\block.js
var payloadLength = 0,payloadHash = crypto.createHash('sha256');
transactions = transactions.sort(function compare(a, b) {
    if (a.type == 1) return 1;
    if (a.type < b.type) return -1;
    if (a.type > b.type) return 1;
    if (a.amount < b.amount) return -1;
    if (a.amount > b.amount) return 1;
    return 0;
});

transactions.forEach(function (tx) {
    bytes = getTransactionBytes(tx);
    payloadLength += bytes.length;
    payloadHash.update(bytes);
});

payloadHash = payloadHash.digest();

var block = {
    version: 0,
    reward: 0,
    totalAmount: totalAmount,
    totalFee: 0,
    payloadHash: payloadHash.toString('hex'),
    timestamp: 0,
    numberOfTransactions: transactions.length,
    payloadLength: payloadLength,
    previousBlock: null,
    generatorPublicKey: map_keys[master_id].publicKey,
    transactions: transactions,
    height: 1
};

var bytes = getBytes(block);
block.blockSignature = sign(map_keys[master_id], bytes);
bytes = getBytes(block);
block.id = getId(bytes);
//console.log(util.inspect(block, false, null));

var outputFilename = '/tmp/genesisBlock.json';

fs.writeFile(outputFilename, JSON.stringify(block, null, 2), function(err) {
    if(err) {
      console.log(err);
    } else {
      console.log("JSON saved to " + outputFilename);
    }
}); 