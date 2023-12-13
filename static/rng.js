// JavaScript function to generate 6 random unique values in order and populate form

function luckyDip() {

    // create empty set
    let draw = new Set();

    // while set does not contain 6 values, create a random value between 1 and 60
    let min;
    let max;
    let value;
    while (draw.size < 6) {
        min = 1;
        max = 60;
        let randomBuffer = new Uint32Array(1);
        window.crypto.getRandomValues(randomBuffer);
        let csRandomNumber = randomBuffer[0] / (0xFFFFFFFF);
        value = Math.floor(csRandomNumber * (max - min) + min);

        // sets cannot contain duplicates so value is only added if it does not exist in set
        draw.add(value)
    }

    // turn set into an array
    let a = Array.from(draw);

    // sort array into size order
    a.sort(function (a, b) {
        return a - b;
    });

    // add values to fields in create draw form
    for (let i = 0; i < 6; i++) {
        document.getElementById("no" + (i + 1)).value = a[i];
    }
}

window.addEventListener('load', function () {
    const luckyDipButton = document.getElementById("lucky-dip")
    if (luckyDipButton) {
        luckyDipButton.addEventListener("click", luckyDip);
    }
});