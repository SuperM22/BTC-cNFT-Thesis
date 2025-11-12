fn main(x: u64, y: pub u64) { //name of inputs : type of inputs , public/private
    assert(x != y);
}

#[test]
fn test_main() {
    main(1, 2);

    // Uncomment to make test fail
    // main(1, 1);
}
