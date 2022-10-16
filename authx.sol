pragma solidity ^0.8.0;
contract verio {
 
  struct node{
      address nodeaddress;
      string organisation;
      string noderpc;
  }
  node[] public nodes;
  //address => hash(Jwt mapping)
  struct vote{
      uint yesvote;
      uint novote;
      
  }
  
  mapping (string=>bytes32) public addjhash;
  mapping (bytes32=>address) public jhashadd;
  mapping (bytes32=>bytes32) public addidhash;
  event Nodeadd(address nodeaddress,string organisation);
  mapping (string=>bool) public nodereplacer;
  mapping (string=>vote) public nodevote;
  mapping (string=>bool) public ifvoted;
  mapping (address=>string) public reversenodemap;
  mapping (string=>address) public prenodeaddress;
  mapping (string=>string) public prenoderpc;
    constructor(string memory org,string memory noderpc){
      nodes.push(node(msg.sender,org,noderpc));
      reversenodemap[msg.sender]=org;
   }
    function recoverSigner(bytes32 _ethSignedMessageHash, bytes memory _signature)
        public
        pure
        returns (address)
    {
          bytes memory prefix = "\x19Ethereum Signed Message:\n32";
        (bytes32 r, bytes32 s, uint8 v) = splitSignature(_signature);
  bytes32 prefixedHashMessage = keccak256(abi.encodePacked(prefix, _ethSignedMessageHash));
         
        return ecrecover(prefixedHashMessage, v, r, s);
    }

    function VerifyMessage(bytes32 _hashedMessage, uint8 _v, bytes32 _r, bytes32 _s) public pure returns (address) {
        bytes memory prefix = "\x19Ethereum Signed Message:\n32";
        bytes32 prefixedHashMessage = keccak256(abi.encodePacked(prefix, _hashedMessage));
        address signer = ecrecover(prefixedHashMessage, _v, _r, _s);
        return signer;
    }
   function splitSignature(bytes memory sig)
        public
        pure
        returns ( bytes32 r,bytes32 s,uint8 v)   
    {
        require(sig.length == 65, "invalid signature length");
            
        assembly {
            r := mload(add(sig, 32))
            s := mload(add(sig, 64))
            v := byte(0, mload(add(sig, 96)))
        }
    }
 //getting total numbers of signature(number of signatures)
 function tmp(bytes[] memory _signo)public pure returns(uint){
  return _signo.length;
 }
 function genesisnode() public view returns(string memory){
     return nodes[0].organisation;
 }
 function addnode(string memory organisation,bool _vote) public {
     string memory _organisation=reversenodemap[msg.sender];
     bytes memory isorgempty = bytes(_organisation); 
     require(prenodeaddress[organisation]!=address(0),"no applicant node");

     require(isorgempty.length!=0,"you are not authorized to vote");
     require(ifvoted[string(abi.encodePacked(organisation,"$",_organisation))]!=true,"already voted");
    
     if(_vote==false){
          nodevote[organisation]=vote(nodevote[organisation].yesvote,nodevote[organisation].novote+1);
      ifvoted[string(abi.encodePacked(organisation,"$",_organisation))]=true;
     }
     if(_vote==true){
          nodevote[organisation]=vote(nodevote[organisation].yesvote+1,nodevote[organisation].novote);
      ifvoted[string(abi.encodePacked(organisation,"$",_organisation))]=true;
     }
     if(nodevote[organisation].novote+nodevote[organisation].yesvote==nodes.length){

         if(nodevote[organisation].yesvote>=nodevote[_organisation].novote&&nodevote[organisation].yesvote>0){
             
               nodes.push(node(prenodeaddress[organisation],organisation,prenoderpc[organisation]));  
               nodereplacer[organisation]=true;
                reversenodemap[prenodeaddress[organisation]]=organisation;
         }
         else{
               nodereplacer[organisation]=false;
         }
     }
      
 }

 function nodeatindex(uint8 i) public view returns(string memory){
     return nodes[i].organisation;
 }
function nodecount() public view returns(uint){
     return nodes.length;
 }

function authxlogin(bytes32 jwthash,address contractadd) public{
require(addidhash[jwthash] == 0,"jwt already used!");
string memory y=string(abi.encodePacked(string(abi.encodePacked(msg.sender)),"$",string(abi.encodePacked(contractadd))));
addjhash[y]=jwthash;
addidhash[jwthash]=bytes32("none");
}
function nodeaddreq(string memory organisation,string memory noderpc) public {
for (uint x=0; x<nodes.length; x++) 
{
 if(keccak256(abi.encodePacked(nodes[x].organisation))==keccak256(abi.encodePacked(organisation))){
 revert(); 
 } 
}
require(nodereplacer[organisation]==false,"organisation voting pending wait for result to reapply or denied");
emit Nodeadd(msg.sender,organisation);
nodereplacer[organisation]=true;
prenodeaddress[organisation]=msg.sender;
prenoderpc[organisation]=noderpc;
}  

function authrsign(bytes32 jwthash,bytes32 whois,bytes[] memory _verifysigno,bytes[] memory _whoissigno) public{
require(_verifysigno.length==nodes.length,"Invalid number of verifier signature");
require(_whoissigno.length==nodes.length,"Invalid number of whoissigno signature");
 uint jwtvote;
 uint whovote;
 for(uint i=0; i<nodes.length; i++){
        if(nodes[i].nodeaddress==recoverSigner(jwthash, _verifysigno[i])){
            jwtvote++;
        }
         if(nodes[i].nodeaddress==recoverSigner(whois, _whoissigno[i])){
            whovote++;
        }
        
     }
     require(jwtvote>(nodes.length/2),"auth failed jwtvote");
        require(whovote>(nodes.length/2),"auth failed whovote");

        addidhash[jwthash]=whois;
}
function op(string memory organisation) public view returns(uint){
  return nodevote[organisation].yesvote;
}
function islogin(address contractadd) public view returns(bool){
string memory y=string(abi.encodePacked(string(abi.encodePacked(msg.sender)),"$",string(abi.encodePacked(contractadd))));
if(addjhash[y]==""){
    return false;
}
else{
 
    if(addidhash[addjhash[y]]==bytes32("none")){
        return false;
    }
    else{
        return true;
    }
}
}
function logout(address contractadd) public {
string memory y=string(abi.encodePacked(string(abi.encodePacked(msg.sender)),"$",string(abi.encodePacked(contractadd))));
require(islogin(contractadd)==true,"you are not logged in");
addjhash[y]="";
//addidhash[addjhash[y]]=bytes32("none");
}

function getid(address contractadd) public view returns(bytes32){
   require(islogin(contractadd)==true,"you are not logged in");
   string memory y=string(abi.encodePacked(string(abi.encodePacked(msg.sender)),"$",string(abi.encodePacked(contractadd))));
   return addidhash[addjhash[y]];  
}


//function whois(address contractadd) public view  
/* just for testing recoverSigner testing
function authsign1(bytes32 jwthash,bytes32 whois,bytes[] memory _verifysigno,bytes[] memory _whoissigno) public  pure returns(address){
 address na;
        na=recoverSigner(jwthash, _verifysigno[0]);
     return na;
}
function authsign2(bytes32 jwthash,bytes32 whois,bytes[] memory _verifysigno,bytes[] memory _whoissigno) public  pure returns(address){
 address na;
        na=recoverSigner(jwthash, _verifysigno[1]);
     return na;
}
function authsign3(bytes32 jwthash,bytes32 whois,bytes[] memory _verifysigno,bytes[] memory _whoissigno) public  pure returns(address){
 address na;
        na=recoverSigner(whois, _whoissigno[0]);
     return na;
}
function authsign4(bytes32 jwthash,bytes32 whois,bytes[] memory _verifysigno,bytes[] memory _whoissigno) public  pure returns(address){
 address na;
        na=recoverSigner(whois, _whoissigno[1]);
     return na;
}
function au(bytes32 jw,bytes[] memory x) public returns(address){
address na;
        na=recoverSigner(jw,x[0]);
     return na;
}
    function mv(bytes32 _hashedMessage, uint8 _v, bytes32 _r, bytes32 _s) public pure returns (address) {
        bytes memory prefix = "\x19Ethereum Signed Message:\n32";
        bytes32 prefixedHashMessage = keccak256(abi.encodePacked(prefix, _hashedMessage));
        address signer = ecrecover(prefixedHashMessage, _v, _r, _s);
        return signer;
    }
    */


}
