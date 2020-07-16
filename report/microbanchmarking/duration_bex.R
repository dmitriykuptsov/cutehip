d<-scan("duration_bex.dat")
pdf("duration_bex.pdf", height=4)
hist(d, col="dark red", xlab="BEX duration, seconds", ylab="Frequency", main="");
grid(col="black", lwd=2)
dev.off()
