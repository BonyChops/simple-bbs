document.body.onload = () => {
    var elements = document.getElementsByClassName("fade-in");
    for(const element of elements){
        element.classList.add("fade-in-active");
        element.classList.remove("fade-in");
    }
}