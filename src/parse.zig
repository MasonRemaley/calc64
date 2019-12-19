const std = @import("std");
const Tokenizer = @import("tokenize.zig").Tokenizer;
const Token = @import("tokenize.zig").Token;
const Inst = @import("../main.zig").Inst;

const Expr = union(enum) {
    literal: i8,
    math: struct {
        lhs: *Expr,
        op: Op,
        rhs: *Expr,
    },
};

const Op = @TagType(Inst);

const Context = struct {
    source: []const u8,
    tok_i: usize,
    tokenizer: Tokenizer,
    allocator: *std.mem.Allocator,
    put_back_buffer: [1]Token,
    put_back_count: u1,

    fn eatToken(self: *Context, id: Token.Id) ?Token {
        const token = self.nextToken();
        if (token.id == id) return token;
        self.putBackToken(token);
        return null;
    }

    fn nextToken(self: *Context) Token {
        if (self.put_back_count == 0) {
            return self.tokenizer.next();
        } else {
            self.put_back_count -= 1;
            return self.put_back_buffer[self.put_back_count];
        }
    }

    fn putBackToken(self: *Context, token: Token) void {
        self.put_back_buffer[self.put_back_count] = token;
        self.put_back_count += 1;
    }

    fn tokenSlice(self: *Context, token: Token) []const u8 {
        return self.source[token.start..token.end];
    }
};

pub fn parse(source: []const u8) ![]Inst {
    const stdout = &std.io.getStdOut().outStream().stream;
    var context = Context{
        .source = source,
        .tok_i = 0,
        .tokenizer = Tokenizer.init(source),
        .allocator = std.heap.page_allocator,
        .put_back_buffer = undefined,
        .put_back_count = 0,
    };
    const root = try parseExpr(&context);
    printTree(root);
    var list = std.ArrayList(Inst).init(context.allocator);
    try renderTree(root, &list);
    return list.toOwnedSlice();
}

fn printTree(node: *Expr) void {
    switch (node.*) {
        .literal => |x| {
            std.debug.warn("{}", .{x});
        },
        .math => |math| {
            std.debug.warn("( ", .{});
            printTree(math.lhs);
            std.debug.warn(" {} ", .{math.op});
            printTree(math.rhs);
            std.debug.warn(" )", .{});
        },
    }
}

fn renderTree(node: *Expr, list: *std.ArrayList(Inst)) !void {
    switch (node.*) {
        .literal => |x| {
            try list.append(Inst{.add = x });
        },
        .math => |math| {
            renderTree(math.lhs, list);
            renderTree(math.rhs, list);
            switch (math.op) {
                .add => try list.append(Inst{.add = }),
                .div => try list.append(Inst{.add = }),
            }
        },
    }
}

fn parseExpr(ctx: *Context) anyerror!*Expr {
    const first_tok = ctx.nextToken();
    if (first_tok.id == .lparen) {
        const lhs = try parseExpr(ctx);
        const tok_op = ctx.nextToken();
        const op: Op = switch (tok_op.id) {
            .plus => .add,
            .slash => .div,
            else => return error.ParseError,
        };

        const rhs = try parseExpr(ctx);
        const rparen = ctx.eatToken(.rparen) orelse return error.ParseError;

        const expr = try ctx.allocator.create(Expr);
        expr.* = Expr{ .math = .{
            .lhs = lhs,
            .op = op,
            .rhs = rhs,
        }};
        return expr;
    } else if (first_tok.id == .integer_literal) {
        const x = try std.fmt.parseInt(i8, ctx.tokenSlice(first_tok), 10);
        const expr = try ctx.allocator.create(Expr);
        expr.* = Expr{.literal = x};
        return expr;
    } else {
        return error.ParseError;
    }
}
