    var countDownDate = Date.now() + (250 * 60 * 60);

    // Atualize a contagem decrescente a cada 1 segundo
    var x = setInterval(function () {

    // Obtém a data e hora de hoje
    var now = new Date().getTime();

    // Obtém a distância entre agora e a data de contagem decrescente
    var distance = countDownDate - now;

    // Cálcula o tempo por dias, horas, minutos e segundos
    var minutes = Math.floor((distance % (1000 * 60 * 60)) / (1000 * 60));
    var seconds = Math.floor((distance % (1000 * 60)) / 1000);

    document.getElementById("timer").innerHTML = minutes + "m " + seconds + "s ";

    // Se a contagem decrescente terminar, escreva algum texto
    if (distance < 0)
    {
        clearInterval(x);
        document.getElementById("timer").innerHTML = "Sessão expírada...";
    }
}, 1000);