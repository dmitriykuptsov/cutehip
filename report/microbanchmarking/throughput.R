ipsec<-scan("throughput_ipsec.dat")
no_ipsec<-scan("throughput_no_ipsec.dat")
summary(ipsec);
summary(no_ipsec);
pdf("throughput.pdf", height=4);
plot(ecdf(ipsec), col="dark red", lwd=6, main="", ylab="Probability", xlab="Throughput, Mb/s", log="x", verticals=T, do.points=F, xlim=c(1, 42));
plot(ecdf(no_ipsec), col="dark blue", lwd=6, add=T, verticals=T, do.points=F);
grid(col="black");
legend("bottomright", c("IPSec", "Plain TCP"), col=c("dark red", "dark blue"), bty="n", lwd=c(3, 3));
dev.off();
