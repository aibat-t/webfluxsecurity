package kz.aibat.webfluxsecurity.mapper;

import kz.aibat.webfluxsecurity.dto.UserDto;
import kz.aibat.webfluxsecurity.entity.UserEntity;
import org.mapstruct.InheritInverseConfiguration;
import org.mapstruct.Mapper;

@Mapper(componentModel = "spring")
public interface UserMapper {
    UserDto map(UserEntity userEntity);

    @InheritInverseConfiguration
    UserEntity map(UserDto userDto);
}
