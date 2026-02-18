SECTIONS
{
    .text :
    {
        *( .text$A );
        *( .text$B );
        *( .text );
        *( .rdata* );
        *( .text$C );
    }
}