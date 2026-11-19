document.addEventListener("DOMContentLoaded", function () {
    const title = document.querySelector(".title");
    title.style.opacity = "0";
    title.style.transform = "translateY(-30px)";
    
    setTimeout(() => {
        title.style.opacity = "1";
        title.style.transform = "translateY(0)";
        title.style.transition = "opacity 1s ease, transform 1s ease";
    }, 500);
});