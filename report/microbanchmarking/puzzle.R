data<-read.table("puzzle_solution_perf.dat");
agg<-aggregate(data[, 3], list(data$V1), mean);
names(agg)<-c("difficulty", "duration")
print(agg$difficulty);
pdf("puzzle_solution_perf.pdf", height=4);
plot(agg$difficulty, agg$duration, main="Average time, needed to solve a puzzle, expressed in seconds", xlab="Puzzle difficulty, bits", ylab="Average duration, seconds", col="dark red", lwd=4, pch=4, type="b", xlim=c(0, 20));
grid(col="grey", lwd=2);
dev.off();
