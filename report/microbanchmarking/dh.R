data<-read.table("DH.dat", sep=",");
pdf("dh_computation_hist.pdf")
par(mfrow=c(3, 1))
summary(data*1000);
# https://datatracker.ietf.org/doc/rfc3526/?include_text=1
hist(data[data$V1==14, 2]*1000, col="dark blue", xlab="Time, ms", ylab="Probability", main="DH 2048 bits", prob=T, breaks=30);
grid(col="black");
hist(data[data$V1==16, 2]*1000, col="dark red", xlab="Time, ms", ylab="Probability", main="DH 4096 bits", prob=T, breaks=30);
grid(col="black");
hist(data[data$V1==18, 2]*1000, col="gray", xlab="Time, ms", ylab="Probability", main="DH 8192 bits", prob=T, breaks=30);
grid(col="black");
dev.off();
