pub mod enroll;
pub mod protect;
pub mod settings;
pub mod setup;

use serenity::all::{Context, GuildId};

pub async fn register_all(ctx: &Context, guild_id: GuildId) -> serenity::Result<()> {
    for command in setup::commands()
        .into_iter()
        .chain(protect::commands())
        .chain(settings::commands())
        .chain(enroll::commands())
    {
        guild_id.create_command(&ctx.http, command).await?;
    }
    Ok(())
}
