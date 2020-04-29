data<-read.table("ECDH.dat", sep=",");
pdf("ecdh_computation_hist.pdf")
par(mfrow=c(3, 1))
summary(data*1000);
# https://datatracker.ietf.org/doc/rfc3526/?include_text=1
hist(data[data$V1==19, 2]*1000, col="dark blue", xlab="Time, ms", ylab="Probability", main="ECDH 256 bits", prob=T, breaks=30);
grid(col="black");
hist(data[data$V1==20, 2]*1000, col="dark red", xlab="Time, ms", ylab="Probability", main="ECDH 384 bits", prob=T, breaks=30);
grid(col="black");
hist(data[data$V1==21, 2]*1000, col="gray", xlab="Time, ms", ylab="Probability", main="ECDH 521 bits", prob=T, breaks=30);
grid(col="black");
dev.off();
