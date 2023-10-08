package org.nsu.cli;

import java.io.PrintWriter;
import java.io.StringWriter;
import org.apache.commons.cli.CommandLine;
import org.apache.commons.cli.DefaultParser;
import org.apache.commons.cli.HelpFormatter;
import org.apache.commons.cli.Options;
import org.apache.commons.cli.ParseException;

public class CLI {

    private static final Options options = new Options();

    static {
        options.addOption("p", "port", true, "server port");
        options.addOption("h", "help", false, "...");
    }

    public static int parse(String[] args) {
        CommandLine cmd;
        try {
            cmd = new DefaultParser().parse(options, args);
        } catch (ParseException e) {
            throw new RuntimeException(e);
        }
        int port;
        if (cmd.hasOption("help")) {
            System.out.println(usage());
            System.exit(0);
        }
        if (cmd.hasOption("p")) {
            port = Integer.parseInt(cmd.getOptionValue("p"));
            if (port <= 0) {
                throw new RuntimeException("wrong port");
            }
        }else {
            throw new RuntimeException("No required option p");
        }
        return port;
    }

    public static String usage() {
        HelpFormatter formatter = new HelpFormatter();
        StringWriter stringWriter = new StringWriter();
        formatter.printHelp(new PrintWriter(stringWriter), 250, "proxy", null,
                options, formatter.getLeftPadding(), formatter.getDescPadding(), null, true);
        return stringWriter.toString();
    }
}