
let obj = {};

console.log(obj?.settings?.test ?? "not set");

obj = {
    settings: {}
};

console.log(obj?.settings?.test ?? "not set");

obj = {
    settings: {
        test: "here we are"
    }
};

console.log(obj?.settings?.test ?? "not set");

obj = null;
console.log(obj?.settings?.test ?? "not set");
