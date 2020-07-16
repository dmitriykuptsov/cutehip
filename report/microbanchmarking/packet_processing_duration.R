d<-read.table("duration_packets.dat", sep="\t")
pdf("packet_processing.pdf", height=4)
print(d);
names(d)<-c("I1", "R1", "I2", "R2");
boxplot(d, use.cols = TRUE, main="", xlab="Packet type", ylab="Duration, seconds");
grid(col="black", lwd=2)
dev.off();
