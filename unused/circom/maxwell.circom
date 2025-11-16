// zkcpsimple_poseidon.circom
pragma circom 2.1.6;

include "./circomlib/circuits/poseidon.circom";

template ZKCP_PoseidonOnly() {
    // PRIVATE inputs
    signal input k;   // field
    signal input s;   // field

    // PUBLIC outputs
    signal output ct; // Poseidon(k, s)
    signal output h;  // Poseidon(k)

    // h = Poseidon(k)
    component Hk = Poseidon(1);
    Hk.inputs[0] <== k;
    h <== Hk.out;

    // ct = Poseidon(k, s)
    component Hks = Poseidon(2);
    Hks.inputs[0] <== k;
    Hks.inputs[1] <== s;
    ct <== Hks.out;

    // debugging:
    // log("k=", k);
    // log("s=", s);
    // log("h=", h);
    // log("ct=", ct);
}

component main = ZKCP_PoseidonOnly();